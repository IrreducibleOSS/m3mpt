// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct SkipListHeaderAdvice {
    list_ptr: u32,
    prefix_val: u8,
    offset: u32,
    first_child_ptr: u32,
}

struct RowMajors {
    list_ptr: B32,
    prefix_val: B8,
    prefix_ts: B32,
    offset: B32,
    first_child_ptr: B32,
    offset_lookup_ts: B32,
}

pub(crate) struct SkipListHeaderTable {
    count: usize,
    index: usize,
    n_vars: usize,
    _smallest_tower_level: usize,
    data: Vec<RowMajors>,
}

impl FunctionTable for SkipListHeaderTable {
    type Data = SkipListHeaderAdvice;
    fn new() -> Self {
        Self {
            count: 0,
            index: 0,
            n_vars: 0,
            _smallest_tower_level: 5,
            data: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.data = Vec::with_capacity(count);

        self.count = count;
        self.n_vars = std::cmp::max(
            self.count.next_power_of_two().trailing_zeros() as usize,
            U::LOG_BITS + 3, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data) {
        let mem = &mut mpt_state.mem;
        self.data.push(RowMajors {
            list_ptr: mem.to_mult(data.list_ptr),
            prefix_val: B8::from_underlier(data.prefix_val),
            prefix_ts: mem.process_timestamp(data.list_ptr),
            offset: mem.to_mult(data.offset),
            first_child_ptr: mem.to_mult(data.first_child_ptr),
            offset_lookup_ts: mpt_state
                .skip_list_header_offset_lookup
                .process_timestamp(data.prefix_val),
        });

        self.index += 1;
    }
    #[instrument(
        name = "skip_list_header",
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
        builder.push_namespace("skip_list_header");
        if builder.witness().is_some() {
            assert_eq!(self.index, self.count);
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let list_ptr = builder.add_committed("list_ptr", n_vars, B32::TOWER_LEVEL);
        let prefix_val = builder.add_committed("prefix_val", n_vars, B8::TOWER_LEVEL);
        let prefix_ts = builder.add_committed("prefix_ts", n_vars, B32::TOWER_LEVEL);
        let offset = builder.add_committed("offset", n_vars, B32::TOWER_LEVEL);
        let first_child_ptr = builder.add_committed("first_child_ptr", n_vars, B32::TOWER_LEVEL);
        let offset_lookup_ts = builder.add_committed("offset_lookup_ts", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.data;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (list_ptr, B32),
                    (prefix_val, B8),
                    (offset, B32),
                    (first_child_ptr, B32),
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [
                    (prefix_ts, B32, B32::one()),
                    (offset_lookup_ts, B32, B32::one())
                ]
            );
        }

        // from skip_list_header pull (list_ptr, first_child_ptr)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [(list_ptr, basis(32, 0)), (first_child_ptr, basis(32, 1))],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(list_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(first_child_ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, list_ptr, first_child_ptr)| {
                        *block = (*first_child_ptr as u128) << 32 | (*list_ptr as u128);
                    });
            }

            builder.receive(channel_ids.skip_list_header, count, [block0]);
        }
        // mem reads
        {
            read_mem(
                builder,
                "prefix_val",
                list_ptr,
                prefix_val,
                prefix_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
        }
        // read offset from offset_lookup
        {
            // from offset_lookup pull (prefix_val, offset, offset_lookup_ts)
            let read_block = builder.add_linear_combination(
                "flush 1, read_block",
                n_vars,
                [
                    (prefix_val, basis(32, 0)),
                    (offset, basis(32, 1)),
                    (offset_lookup_ts, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness
                        .new_column::<B128>(read_block)
                        .as_mut_slice::<u128>(),
                    witness.get::<B8>(prefix_val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                    witness.get::<B32>(offset_lookup_ts)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, prefix_val, offset, offset_lookup_ts)| {
                        *block = (*offset_lookup_ts as u128) << 64
                            | (*offset as u128) << 32
                            | (*prefix_val as u128);
                    });
            }
            builder.receive(
                channel_ids.skip_list_header_offset_lookup,
                count,
                [read_block],
            );

            // to offset_lookup push (prefix_val, offset, offset_lookup_ts * g)
            let write_block = builder.add_linear_combination(
                "flush 1, write_block",
                n_vars,
                [
                    (prefix_val, basis(32, 0)),
                    (offset, basis(32, 1)),
                    (
                        offset_lookup_ts,
                        basis(32, 2) * B32::MULTIPLICATIVE_GENERATOR,
                    ),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness
                        .new_column::<B128>(write_block)
                        .as_mut_slice::<u128>(),
                    witness.get::<B8>(prefix_val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                    witness.get::<B32>(offset_lookup_ts)?.as_slice::<B32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, prefix_val, offset, offset_lookup_ts)| {
                        let incremented_ts = (*offset_lookup_ts) * B32::MULTIPLICATIVE_GENERATOR;
                        *block = (incremented_ts.to_underlier() as u128) << 64
                            | (*offset as u128) << 32
                            | (*prefix_val as u128);
                    });
            }
            builder.send(
                channel_ids.skip_list_header_offset_lookup,
                count,
                [write_block],
            );

            builder.assert_not_zero(offset_lookup_ts);
        }
        // list_ptr * offset == first_child_ptr
        {
            builder.assert_zero(
                [list_ptr, offset, first_child_ptr],
                binius_macros::arith_expr!(
                    [list_ptr, offset, first_child_ptr] = first_child_ptr - list_ptr * offset
                )
                .convert_field(),
            );
        }

        builder.pop_namespace();
        Ok(())
    }
}
impl MPT {
    pub(crate) fn skip_list_header(&mut self, action: Action, list_ptr: u32) -> u32 {
        let prefix_val = self.state.mem[list_ptr];
        let offset = MPT::skip_list_header_offset_lookup(prefix_val) as u32;
        let first_child_ptr = list_ptr + offset;
        match action {
            Action::Append => {
                self.skip_list_header_table.append(
                    &mut self.state,
                    SkipListHeaderAdvice {
                        list_ptr,
                        prefix_val,
                        offset,
                        first_child_ptr,
                    },
                );
            }
            Action::Count => {
                self.skip_list_header_count += 1;
            }
            Action::Ignore => (),
        }
        first_child_ptr
    }
}
