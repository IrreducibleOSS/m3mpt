// Copyright 2024 Irreducible Inc.

use super::*;
pub(crate) struct HashTransData {
    state: State,
    preimage_ptr: u32,
}
struct ColMajors {
    state_key_ptr_parity: BitVec,
}
struct RowMajors {
    state_start_ptr: B32,
    state_key_ptr_byte: B32,
    state_rlp_ptr: B32,
    state_ts: B32,
    preimage_ptr: B32,
    prefix_val_ts: B32,
}
pub(crate) struct HashTransTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    col_majors: ColMajors,
    row_majors: Vec<RowMajors>,
}

impl FunctionTable for HashTransTable {
    type Data = HashTransData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 0,
            col_majors: ColMajors {
                state_key_ptr_parity: BitVec::new(None),
            },
            row_majors: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.col_majors.state_key_ptr_parity = BitVec::new(Some(count));
        self.row_majors = Vec::with_capacity(count);

        self.count = count;
        self.n_vars = std::cmp::max(
            self.count.next_power_of_two().trailing_zeros() as usize,
            U::LOG_BITS + 3, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data) {
        let mem = &mut mpt_state.mem;
        self.col_majors
            .state_key_ptr_parity
            .push(data.state.key_ptr.parity);
        self.row_majors.push(RowMajors {
            state_start_ptr: mem.to_mult(data.state.start_ptr),
            state_key_ptr_byte: mem.to_mult(data.state.key_ptr.byte),
            state_rlp_ptr: mem.to_mult(data.state.rlp_ptr),
            state_ts: data.state.ts,
            preimage_ptr: mem.to_mult(data.preimage_ptr),
            prefix_val_ts: mem.process_timestamp(data.state.rlp_ptr),
        });

        self.index += 1;
    }
    #[instrument(
        name = "hash_trans",
        fields(n_vars = n_vars)
        skip_all,
        level = "debug"
    )]
    fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
        TableHeight { n_vars, count }: TableHeight,
    ) -> Result<(), anyhow::Error> {
        builder.push_namespace("hash_trans");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let state_start_ptr = builder.add_committed("state_start_ptr", n_vars, B32::TOWER_LEVEL);
        let state_key_ptr_byte =
            builder.add_committed("state_key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let state_rlp_ptr = builder.add_committed("state_rlp_ptr", n_vars, B32::TOWER_LEVEL);
        let state_ts = builder.add_committed("state_ts", n_vars, B32::TOWER_LEVEL);
        let preimage_ptr = builder.add_committed("preimage_ptr", n_vars, B32::TOWER_LEVEL);
        let prefix_val_ts = builder.add_committed("prefix_val_ts", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (state_start_ptr, B32),
                    (state_key_ptr_byte, B32),
                    (state_rlp_ptr, B32),
                    (state_ts, B32),
                    (preimage_ptr, B32),
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [(prefix_val_ts, B32, B32::one())]
            );
        }

        let poly = binius_core::transparent::constant::Constant::new(n_vars, B128::zero());
        let initial_state = (0..12)
            .map(|_| builder.add_transparent("initial_state", poly))
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(witness) = builder.witness() {
            initial_state.iter().for_each(|id| {
                witness.new_column::<B128>(*id);
            });
        }

        let state_key_ptr_parity =
            builder.add_committed("state_key_parity_ptr", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.col_majors.state_key_ptr_parity,
                witness
                    .new_column::<B1>(state_key_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(|(source_byte_state_key, dest_byte_state_key)| {
                    *dest_byte_state_key = source_byte_state_key;
                });
        }

        // from state pull (state_start_ptr, state_key_ptr_byte, state_rlp_ptr, state_ts; state_key_ptr_parity)
        {
            flush_state(
                builder,
                FlushDirection::Pull,
                state_start_ptr,
                state_key_ptr_byte,
                state_rlp_ptr,
                state_ts,
                state_key_ptr_parity,
                n_vars,
                count,
                channel_ids.state,
            )?;
        }
        // read 0xa0 from mem
        {
            read_const(
                builder,
                "0xa0",
                state_rlp_ptr,
                B8::new(0xa0),
                prefix_val_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
        }
        // to absorb_block push (preimage_ptr, state_rlp_ptr, initial_state)
        {
            let block0 = builder.add_linear_combination(
                "block 0, flush 0",
                n_vars,
                [(preimage_ptr, basis(32, 0)), (state_rlp_ptr, basis(32, 1))],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(preimage_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(state_rlp_ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, a, b)| {
                        *block = (*b as u128) << 32 | (*a as u128);
                    });
            }

            let mut all_blocks = vec![block0];
            all_blocks.extend(initial_state);

            builder.send(channel_ids.absorb_block, count, all_blocks);
        }
        // to state push (state_start_ptr, state_key_ptr_byte, preimage_ptr, state_ts; state_key_ptr_parity)
        {
            flush_state(
                builder,
                FlushDirection::Push,
                state_start_ptr,
                state_key_ptr_byte,
                preimage_ptr,
                state_ts,
                state_key_ptr_parity,
                n_vars,
                count,
                channel_ids.state,
            )?;
        }

        builder.pop_namespace();
        Ok(())
    }
}
impl MPT {
    pub(crate) fn hash_trans(&mut self, action: Action, preimage_ptr: u32, state: State) -> State {
        let u8_val = self.state.mem[state.rlp_ptr];
        assert_eq!(u8_val, 0xa0);
        let post_preimage_ptr = self.skip_list(preimage_ptr);
        let preimage_length = post_preimage_ptr - preimage_ptr;
        let total_blocks = (preimage_length / (HASH_R as u32) + 1) as u8;
        let hash_input = &self.state.mem[preimage_ptr..post_preimage_ptr];
        let hash = alloy::primitives::keccak256(hash_input);
        for j in 0..32 {
            assert_eq!(self.state.mem[state.rlp_ptr + 1 + j], hash[j as usize]);
        }
        // all the above is dev checks and prover computation

        let initial_state: Vec<u8> = vec![0; HASH_B];
        self.absorb_block(
            action,
            initial_state.try_into().unwrap(),
            preimage_ptr,
            state.rlp_ptr,
            total_blocks,
        );
        let new_state = State {
            start_ptr: state.start_ptr,
            key_ptr: state.key_ptr,
            rlp_ptr: preimage_ptr,
            ts: state.ts,
        };
        match action {
            Action::Append => self.hash_trans_table.append(
                &mut self.state,
                HashTransData {
                    state,
                    preimage_ptr,
                },
            ),
            Action::Count => self.hash_trans_count += 1,
            Action::Ignore => (),
        }
        new_state
    }
}
