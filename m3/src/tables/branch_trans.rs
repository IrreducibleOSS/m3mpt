// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct BranchTransData {
    state: State,
    first_child_ptr: u32,
    first_child_val: u8,
    key_val: u8,
    new_hash_ptr: u32,
    new_key_ptr: NibPtr,
}

struct ColMajors {
    state_key_ptr_parity: BitVec,
}

struct RowMajors {
    state_start_ptr: B32,
    state_key_ptr_byte: B32,
    state_rlp_ptr: B32,
    state_ts: B32,
    key_val: B8,
    key_ts: B32,
    first_child_ptr: B32,
    first_child_val: B8,
    first_child_ts: B32,
    index_nib: B8,
    shift_lookup_ts: B32,
    new_hash_ptr: B32,
    new_key_ptr_byte: B32,
}

pub(crate) struct BranchTransTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    col_majors: ColMajors,
    row_majors: Vec<RowMajors>,
}
impl FunctionTable for BranchTransTable {
    type Data = BranchTransData;
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
        self.col_majors = ColMajors {
            state_key_ptr_parity: BitVec::new(Some(count)),
        };
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
            key_val: B8::from_underlier(data.key_val),
            key_ts: mem.process_timestamp(data.state.key_ptr.byte),
            first_child_ptr: mem.to_mult(data.first_child_ptr),
            first_child_val: B8::from_underlier(data.first_child_val),
            first_child_ts: mem.process_timestamp(data.first_child_ptr),
            index_nib: BranchTransShiftLookup::query(data.state.key_ptr.parity, data.key_val),
            shift_lookup_ts: mpt_state
                .branch_trans_shift_lookup
                .process_timestamp(data.state.key_ptr.parity, data.key_val),
            new_hash_ptr: mem.to_mult(data.new_hash_ptr),
            new_key_ptr_byte: mem.to_mult(data.new_key_ptr.byte),
        });

        self.index += 1;
    }
    #[instrument(
        name = "branch_trans",
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
        builder.push_namespace("branch_trans");
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
        let key_val = builder.add_committed("key_val", n_vars, B8::TOWER_LEVEL);
        let key_ts = builder.add_committed("key_ts", n_vars, B32::TOWER_LEVEL);
        let first_child_ptr = builder.add_committed("first_child_ptr", n_vars, B32::TOWER_LEVEL);
        let first_child_val = builder.add_committed("first_child_val", n_vars, B8::TOWER_LEVEL);
        let first_child_ts = builder.add_committed("first_child_ts", n_vars, B32::TOWER_LEVEL);
        let index_nib = builder.add_committed("index_nib", n_vars, B8::TOWER_LEVEL);
        let shift_lookup_ts = builder.add_committed("shift_lookup_ts", n_vars, B32::TOWER_LEVEL);
        let new_hash_ptr = builder.add_committed("new_hash_ptr", n_vars, B32::TOWER_LEVEL);
        let new_key_ptr_byte = builder.add_committed("new_key_byte_ptr", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (state_start_ptr, B32),
                    (state_key_ptr_byte, B32),
                    (state_rlp_ptr, B32),
                    (key_val, B8),
                    (first_child_ptr, B32),
                    (index_nib, B8),
                    (shift_lookup_ts, B32),
                    (new_hash_ptr, B32),
                    (new_key_ptr_byte, B32)
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [
                    (state_ts, B32, B32::one()),
                    (first_child_val, B8, B8::new(128)),
                    (first_child_ts, B32, B32::one()),
                    (key_ts, B32, B32::one()),
                ]
            );
        }

        let state_key_ptr_parity =
            builder.add_committed("state_key_ptr_parity", n_vars, B1::TOWER_LEVEL);
        let new_key_ptr_parity = builder.add_linear_combination_with_offset(
            "new_key_ptr_parity",
            n_vars,
            B128::one(),
            [(state_key_ptr_parity, B128::one())],
        )?;
        if let Some(witness) = builder.witness() {
            (
                self.col_majors.state_key_ptr_parity,
                witness
                    .new_column::<B1>(state_key_ptr_parity)
                    .as_mut_slice::<u8>(),
                witness
                    .new_column_with_default::<B1>(new_key_ptr_parity, B1::one())
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(
                    |(
                        state_key_ptr_parity_src,
                        state_key_ptr_parity_dest,
                        new_key_ptr_parity_dest,
                    )| {
                        *state_key_ptr_parity_dest = state_key_ptr_parity_src;
                        *new_key_ptr_parity_dest = !state_key_ptr_parity_src;
                    },
                );
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
        // to skip_list_header push (state_rlp_ptr, first_child_ptr)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (state_rlp_ptr, basis(32, 0)),
                    (first_child_ptr, basis(32, 1)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(state_rlp_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(first_child_ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, state_rlp_ptr, first_child_ptr)| {
                        *block = (*first_child_ptr as u128) << 32 | (*state_rlp_ptr as u128);
                    });
            }

            builder.send(channel_ids.skip_list_header, count, [block0]);
        }
        // mem reads
        {
            read_mem(
                builder,
                "first_child_val",
                first_child_ptr,
                first_child_val,
                first_child_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
            read_mem(
                builder,
                "first_child_val",
                state_key_ptr_byte,
                key_val,
                key_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
        }
        // to get_child push (first_child_ptr, index_nib, new_hash_ptr)
        {
            let block0 = builder.add_linear_combination(
                "flush k, block 0",
                n_vars,
                [
                    (first_child_ptr, basis(32, 0)),
                    (index_nib, basis(32, 1)),
                    (new_hash_ptr, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(first_child_ptr)?.as_slice::<u32>(),
                    witness.get::<B8>(index_nib)?.as_slice::<u8>(),
                    witness.get::<B32>(new_hash_ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(
                        |(block, first_child_ptr, index_nib, new_hash_ptr)| {
                            *block = (*new_hash_ptr as u128) << 64
                                | (*index_nib as u128) << 32
                                | (*first_child_ptr as u128);
                        },
                    );
            }

            builder.send(channel_ids.get_child, count, [block0]);
        }
        // to state push (state_start_ptr, new_key_ptr_byte, new_hash_ptr, state_ts; new_key_ptr_parity)
        {
            flush_state(
                builder,
                FlushDirection::Push,
                state_start_ptr,
                new_key_ptr_byte,
                new_hash_ptr,
                state_ts,
                new_key_ptr_parity,
                n_vars,
                count,
                channel_ids.state,
            )?;
        }
        // checking index_nib = U8_TO_MULT_MAP[ (key_val >> (state_key_ptr_parity ? 0 : 4)) & 0x0f ]
        {
            let read_block = builder.add_linear_combination(
                "flush 3, block 0",
                n_vars,
                [
                    (state_key_ptr_parity, basis(8, 0)),
                    (key_val, basis(8, 1)),
                    (index_nib, basis(16, 1)),
                    (shift_lookup_ts, basis(32, 1)),
                ],
            )?;
            builder.receive(channel_ids.branch_trans_shift_lookup, count, [read_block]);

            let write_block = builder.add_linear_combination(
                "flush 3, block 0",
                n_vars,
                [
                    (state_key_ptr_parity, basis(8, 0)),
                    (key_val, basis(8, 1)),
                    (index_nib, basis(16, 1)),
                    (
                        shift_lookup_ts,
                        basis(32, 1) * B32::MULTIPLICATIVE_GENERATOR,
                    ),
                ],
            )?;
            builder.send(channel_ids.branch_trans_shift_lookup, count, [write_block]);

            if let Some(witness) = builder.witness() {
                izip!(
                    witness
                        .new_column::<B128>(read_block)
                        .as_mut_slice::<u128>(),
                    witness
                        .new_column::<B128>(write_block)
                        .as_mut_slice::<u128>(),
                    BitIterator::new(
                        witness.get::<B1>(state_key_ptr_parity)?.as_slice::<u8>(),
                        None,
                    ),
                    witness.get::<B8>(key_val)?.as_slice::<u8>(),
                    witness.get::<B8>(index_nib)?.as_slice::<u8>(),
                    witness.get::<B32>(shift_lookup_ts)?.as_slice::<B32>(),
                )
                .for_each(
                    |(
                        read_block,
                        write_block,
                        state_key_ptr_parity,
                        key_val,
                        index_nib,
                        shift_lookup_ts,
                    )| {
                        let bottom = match state_key_ptr_parity {
                            true => 1,
                            false => 0,
                        };
                        *read_block = ((*shift_lookup_ts).to_underlier() as u128) << 32
                            | (*index_nib as u128) << 16
                            | (*key_val as u128) << 8
                            | bottom;

                        let incremented_ts = *shift_lookup_ts * B32::MULTIPLICATIVE_GENERATOR;
                        *write_block = (incremented_ts.to_underlier() as u128) << 32
                            | (*index_nib as u128) << 16
                            | (*key_val as u128) << 8
                            | bottom;
                    },
                );
            }
        }
        // first_child_val == 0x80 || first_child_val == 0xa0
        {
            let composition = (ArithExpr::Var(0) + ArithExpr::Const(B8::new(128)))
                * (ArithExpr::Var(0) + ArithExpr::Const(B8::new(160)));
            builder.assert_zero([first_child_val], composition.convert_field());
        }
        // new_key_ptr_byte == state_key_ptr_byte * (state_key_ptr_parity ? g : 1)
        {
            let composition = {
                ArithExpr::Var(0)
                    - ArithExpr::Var(1)
                        * (ArithExpr::Var(2) * ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR)
                            + (ArithExpr::one() - ArithExpr::Var(2)))
            };
            builder.assert_zero(
                [new_key_ptr_byte, state_key_ptr_byte, state_key_ptr_parity],
                composition.convert_field(),
            );
        }

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    pub(crate) fn branch_trans(&mut self, action: Action, state: State) -> State {
        let first_child_ptr = self.skip_list_header(action, state.rlp_ptr);
        let first_child_val = self.state.mem[first_child_ptr];
        assert!(first_child_val == 0x80 || first_child_val == 0xa0);
        let key_val = self.state.mem[state.key_ptr.byte];
        let shift = match state.key_ptr.parity {
            true => 0,
            false => 4,
        };
        let index_nib = (key_val >> shift) & 0x0f;
        let new_hash_ptr = self.get_child(action, first_child_ptr, index_nib);
        let new_key_ptr = match state.key_ptr.parity {
            true => NibPtr {
                byte: state.key_ptr.byte + 1,
                parity: false,
            },
            false => NibPtr {
                byte: state.key_ptr.byte,
                parity: true,
            },
        };
        let new_state = State {
            start_ptr: state.start_ptr,
            key_ptr: new_key_ptr,
            rlp_ptr: new_hash_ptr,
            ts: state.ts,
        };
        match action {
            Action::Append => self.branch_trans_table.append(
                &mut self.state,
                BranchTransData {
                    state,
                    first_child_ptr,
                    first_child_val,
                    key_val,
                    new_hash_ptr,
                    new_key_ptr,
                },
            ),
            Action::Count => self.branch_trans_count += 1,
            Action::Ignore => (),
        }
        new_state
    }
}
