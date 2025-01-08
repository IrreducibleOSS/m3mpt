// Copyright 2024 Irreducible Inc.

use super::*;

impl MPT {
    fn create_mem_boundaries(
        mem_channel_id: usize,
        statement: &Statement,
        keys: &[[u8; 32]],
        ptr_ts_pairs: &[PtrTsPair],
    ) -> Vec<Boundary<B128>> {
        let g = B32::MULTIPLICATIVE_GENERATOR;
        use std::iter::successors;
        let mut address_iter = successors(Some(g), |prev| Some(*prev * g));

        // verify the root_hash rlp prefix
        let root_hash_rlp_prefix = verify_mem_read((B32::one(), 0xa0), mem_channel_id);
        // verify the next 32 addresses contain the root hash
        let root_hash_read_boundaries = address_iter
            .by_ref()
            .take(32)
            .zip(statement.root_hash.iter())
            .flat_map(|(addr, &root_hash_byte)| {
                verify_mem_read((addr, root_hash_byte), mem_channel_id)
            })
            .collect::<Vec<_>>();

        // verify each of the keys follows next in mem
        let mut key_read_boundaries = vec![];
        for key in keys {
            key_read_boundaries.extend(
                address_iter
                    .by_ref()
                    .take(32)
                    .zip(key)
                    .flat_map(|(addr, &key_byte)| verify_mem_read((addr, key_byte), mem_channel_id))
                    .collect::<Vec<_>>(),
            );
        }

        let ptr_val_iter = ptr_ts_pairs
            .iter()
            .zip(statement.addr_val_pairs.iter())
            .map(|(ptr_ts_pair, addr_val_pair)| {
                let leaf_val_bytes = &addr_val_pair.value;
                let ptr = ptr_ts_pair.rlp_ptr;
                let val = rlp_encode_long_bytestring(leaf_val_bytes);
                (ptr, val)
            });

        let leaf_val_read_boundaries = ptr_val_iter
            .flat_map(|(rlp_ptr, rlp_leaf_val_bytes)| {
                let starting_addr = g.pow([rlp_ptr as u64]);
                successors(Some(starting_addr), |prev| Some(*prev * g))
                    .zip(rlp_leaf_val_bytes)
                    .flat_map(|(addr, leaf_val_byte)| {
                        verify_mem_read((addr, leaf_val_byte), mem_channel_id)
                    })
            })
            .collect::<Vec<_>>();

        root_hash_rlp_prefix
            .into_iter()
            .chain(root_hash_read_boundaries)
            .chain(key_read_boundaries)
            .chain(leaf_val_read_boundaries)
            .collect()
    }

    // what do we need here?
    fn create_state_boundaries(
        state_channel_id: usize,
        ptr_ts_pairs: &[PtrTsPair],
    ) -> Vec<Boundary<B128>> {
        let g = B32::MULTIPLICATIVE_GENERATOR;
        let mut boundaries = vec![];
        let root_mem_offset = 0;
        let keys_mem_offset = root_mem_offset + 1 + 32;
        // create initial state
        {
            let key_ptr = NibPtr {
                byte: keys_mem_offset,
                parity: false,
            };
            let state = State {
                start_ptr: keys_mem_offset,
                key_ptr,
                rlp_ptr: root_mem_offset,
                ts: B32::one(),
            };
            let state_start_ptr = g.pow([state.start_ptr as u64]);
            let state_key_ptr_byte = g.pow([state.key_ptr.byte as u64]);
            let state_rlp_ptr = g.pow([state.rlp_ptr as u64]);
            let block0 = state_start_ptr * basis(32, 0)
                + state_key_ptr_byte * basis(32, 1)
                + state_rlp_ptr * basis(32, 2)
                + state.ts * basis(32, 3);
            let block1 = parity_to_field(state.key_ptr.parity) * basis(32, 0);
            boundaries.push(Boundary {
                values: vec![block0, block1],
                channel_id: state_channel_id,
                direction: FlushDirection::Push,
                multiplicity: 1,
            });
        }
        // create final states
        for (i, PtrTsPair { rlp_ptr, final_ts }) in ptr_ts_pairs.iter().enumerate() {
            let start_ptr = keys_mem_offset + i as u32 * 32;
            let key_ptr = NibPtr {
                byte: start_ptr + 32,
                parity: false,
            };
            let state = State {
                start_ptr,
                key_ptr,
                rlp_ptr: *rlp_ptr,
                ts: BinaryField32b::new(*final_ts),
            };
            let state_start_ptr = g.pow([state.start_ptr as u64]);
            let state_key_ptr_byte = g.pow([state.key_ptr.byte as u64]);
            let state_rlp_ptr = g.pow([state.rlp_ptr as u64]);
            let block0 = state_start_ptr * basis(32, 0)
                + state_key_ptr_byte * basis(32, 1)
                + state_rlp_ptr * basis(32, 2)
                + state.ts * basis(32, 3);
            let block1 = parity_to_field(state.key_ptr.parity) * basis(32, 0);
            boundaries.push(Boundary {
                values: vec![block0, block1],
                channel_id: state_channel_id,
                direction: FlushDirection::Pull,
                multiplicity: 1,
            });
        }
        boundaries
    }

    // prover and verifier invoked
    #[instrument(skip_all, name = "build", level = "debug")]
    pub fn build(
        mut self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        advice: Advice,
    ) -> Result<(Vec<Boundary<B128>>, Statement), anyhow::Error> {
        // generate channels
        let channel_ids = ChannelIds {
            mem: builder.add_channel(),
            state: builder.add_channel(),
            skip_list_header: builder.add_channel(),
            skip_list_header_offset_lookup: builder.add_channel(),
            keccak_f: builder.add_channel(),
            absorb_block: builder.add_channel(),
            get_child: builder.add_channel(),
            get_child_offset_lookup: builder.add_channel(),
            branch_trans_shift_lookup: builder.add_channel(),
            check_nib: builder.add_channel(),
        };

        let table_heights = advice.table_heights;

        self.skip_list_header_table
            .build(builder, &channel_ids, table_heights.skip_list_header)?;
        self.keccak_f_table
            .build(builder, &channel_ids, table_heights.keccak_f)?;
        self.absorb_block_base_table.build(
            builder,
            &channel_ids,
            table_heights.absorb_block_base_table,
        )?;
        self.absorb_block_recursive_table.build(
            builder,
            &channel_ids,
            table_heights.absorb_block_recursive_table,
        )?;
        self.hash_trans_table
            .build(builder, &channel_ids, table_heights.hash_trans_table)?;
        self.get_child_base_table.build(
            builder,
            &channel_ids,
            table_heights.get_child_base_table,
        )?;
        self.get_child_recursive_table.build(
            builder,
            &channel_ids,
            table_heights.get_child_recursive_table,
        )?;
        self.branch_trans_table
            .build(builder, &channel_ids, table_heights.branch_trans_table)?;
        self.ext_leaf_trans_table.build(
            builder,
            &channel_ids,
            table_heights.ext_leaf_trans_table,
        )?;
        self.check_nib_base_table.build(
            builder,
            &channel_ids,
            table_heights.check_nib_base_table,
        )?;
        self.check_nib_recursive_table.build(
            builder,
            &channel_ids,
            table_heights.check_nib_recursive_table,
        )?;
        self.fork_state_table
            .build(builder, &channel_ids, table_heights.fork_state_table)?;
        self.populate_mem_table.build(
            builder,
            &channel_ids,
            &mut self.state,
            table_heights.populate_mem,
        )?;

        // build lookups
        self.skip_list_header_offset_lookup_table
            .build(builder, &channel_ids)?;
        self.get_child_offset_lookup_table
            .build(builder, &channel_ids)?;
        self.branch_trans_shift_lookup_table
            .build(builder, &channel_ids)?;

        // generate boundaries
        let mut boundaries = vec![];
        boundaries.extend(MPT::create_state_boundaries(
            channel_ids.state,
            &advice.ptr_ts_pairs,
        ));
        boundaries.extend(MPT::create_mem_boundaries(
            channel_ids.mem,
            &self.statement,
            &self.keys,
            &advice.ptr_ts_pairs,
        ));

        Ok((boundaries, self.statement))
    }
}
