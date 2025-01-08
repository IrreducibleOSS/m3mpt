// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct ForkStateData {
    state: State,
    new_key_ptr: NibPtr,
    new_start_ptr: u32,
}

struct ColMajors {
    state_key_ptr_parity: BitVec,
    new_key_ptr_parity: BitVec,
}

struct RowMajors {
    state_start_ptr: B32,
    state_key_ptr_byte: B32,
    state_rlp_ptr: B32,
    state_ts: B32,
    new_start_ptr: B32,
    new_key_ptr_byte: B32,
}

pub(crate) struct ForkStateTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    col_majors: ColMajors,
    row_majors: Vec<RowMajors>,
}

impl FunctionTable for ForkStateTable {
    type Data = ForkStateData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 0,
            col_majors: ColMajors {
                state_key_ptr_parity: BitVec::new(None),
                new_key_ptr_parity: BitVec::new(None),
            },
            row_majors: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.col_majors = ColMajors {
            state_key_ptr_parity: BitVec::new(Some(count)),
            new_key_ptr_parity: BitVec::new(Some(count)),
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
        self.col_majors
            .new_key_ptr_parity
            .push(data.new_key_ptr.parity);

        self.row_majors.push(RowMajors {
            state_start_ptr: mem.to_mult(data.state.start_ptr),
            state_key_ptr_byte: mem.to_mult(data.state.key_ptr.byte),
            state_rlp_ptr: mem.to_mult(data.state.rlp_ptr),
            state_ts: data.state.ts,
            new_start_ptr: mem.to_mult(data.new_start_ptr),
            new_key_ptr_byte: mem.to_mult(data.new_key_ptr.byte),
        });

        self.index += 1;
    }
    #[instrument(
        name = "fork_state",
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
        builder.push_namespace("fork_state");
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
        let new_start_ptr = builder.add_committed("new_start_ptr", n_vars, B32::TOWER_LEVEL);
        let new_key_ptr_byte = builder.add_committed("new_key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (state_start_ptr, B32),
                    (state_key_ptr_byte, B32),
                    (state_rlp_ptr, B32),
                    (new_start_ptr, B32),
                    (new_key_ptr_byte, B32)
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [(state_ts, B32, B32::one()),]
            )
        }

        let state_key_ptr_parity =
            builder.add_committed("state_key_ptr_parity", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.col_majors.state_key_ptr_parity,
                witness
                    .new_column::<B1>(state_key_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(|(src, dest)| {
                    *dest = src;
                });
        }

        let new_key_ptr_parity =
            builder.add_committed("new_key_ptr_parity", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.col_majors.new_key_ptr_parity,
                witness
                    .new_column::<B1>(new_key_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(|(src, dest)| {
                    *dest = src;
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
        // check state_ts != 0
        builder.assert_not_zero(state_ts);
        // to check_nib push (state_key_ptr_byte, new_start_ptr, state_start_ptr, new_key_ptr_byte, state_key_ptr_parity, false, false, new_key_ptr_parity)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (state_key_ptr_byte, basis(32, 0)),
                    (new_start_ptr, basis(32, 1)),
                    (state_start_ptr, basis(32, 2)),
                    (new_key_ptr_byte, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(state_key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(new_start_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(state_start_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(new_key_ptr_byte)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, a, b, c, d)| {
                        *block = (*d as u128) << 96
                            | (*c as u128) << 64
                            | (*b as u128) << 32
                            | (*a as u128);
                    });
            }

            let block1 = builder.add_linear_combination(
                "flush 0, block 1",
                n_vars,
                [
                    (state_key_ptr_parity, basis(32, 0)),
                    (new_key_ptr_parity, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let state_key_ptr_parity_iter = BitIterator::new(
                    witness.get::<B1>(state_key_ptr_parity)?.as_slice::<u8>(),
                    None,
                );

                let new_key_ptr_parity_iteer = BitIterator::new(
                    witness.get::<B1>(new_key_ptr_parity)?.as_slice::<u8>(),
                    None,
                );

                izip!(
                    witness.new_column::<B128>(block1).as_mut_slice::<u128>(),
                    state_key_ptr_parity_iter,
                    new_key_ptr_parity_iteer,
                )
                .for_each(|(block, a, b)| {
                    fn parity_to_num(parity: bool) -> u128 {
                        match parity {
                            true => 1,
                            false => 0,
                        }
                    }
                    *block = parity_to_num(b) << 96 | parity_to_num(a);
                });
            }

            builder.send(channel_ids.check_nib, count, [block0, block1]);
        }
        // to state push (state_start_ptr, state_key_ptr_byte, state_rlp_ptr, state_ts * g; state_key_ptr_parity)
        {
            let g = B32::MULTIPLICATIVE_GENERATOR;
            let block0 = builder.add_linear_combination(
                "state",
                n_vars,
                [
                    (state_start_ptr, basis(32, 0)),
                    (state_key_ptr_byte, basis(32, 1)),
                    (state_rlp_ptr, basis(32, 2)),
                    (state_ts, basis(32, 3) * g),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(state_start_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(state_key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(state_rlp_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(state_ts)?.as_slice::<B32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, start_ptr, key_ptr_byte, rlp_ptr, ts)| {
                        let incremented_ts = *ts * g;
                        *block = (incremented_ts.to_underlier() as u128) << 96
                            | (*rlp_ptr as u128) << 64
                            | (*key_ptr_byte as u128) << 32
                            | (*start_ptr as u128);
                    });
            }

            builder.send(channel_ids.state, count, [block0, state_key_ptr_parity]);
        }
        {
            let block0 = builder.add_linear_combination_with_offset(
                "state",
                n_vars,
                basis(32, 3),
                [
                    (new_start_ptr, basis(32, 0)),
                    (new_key_ptr_byte, basis(32, 1)),
                    (state_rlp_ptr, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(new_start_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(new_key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(state_rlp_ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(
                        |(block, new_start_ptr, new_key_ptr_byte, rlp_ptr)| {
                            *block = (1 << 96)
                                | (*rlp_ptr as u128) << 64
                                | (*new_key_ptr_byte as u128) << 32
                                | (*new_start_ptr as u128);
                        },
                    );
            }

            builder.send(channel_ids.state, count, [block0, new_key_ptr_parity]);
        }
        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    pub(crate) fn fork_state(&mut self, action: Action, state: State, new_start_ptr: u32) {
        let new_key_ptr = self.check_nib(
            action,
            state.key_ptr,
            NibPtr::new(new_start_ptr, false),
            NibPtr::new(state.start_ptr, false),
        );
        match action {
            Action::Append => self.fork_state_table.append(
                &mut self.state,
                ForkStateData {
                    state,
                    new_key_ptr,
                    new_start_ptr,
                },
            ),
            Action::Count => self.fork_state_count += 1,
            Action::Ignore => (),
        }
    }
}
