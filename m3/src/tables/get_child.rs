// Copyright 2024 Irreducible Inc.

use super::*;

impl MPT {
    pub(crate) fn get_child(&mut self, action: Action, ptr: u32, index: u8) -> u32 {
        match index {
            0 => self.get_child_base(action, ptr),
            _ => self.get_child_recursive(action, ptr, index),
        }
    }
}

// BASE
pub(crate) struct GetChildBaseData {
    ptr: u32,
}
pub(crate) struct GetChildBaseTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    ptr: Vec<B32>,
}
impl FunctionTable for GetChildBaseTable {
    type Data = GetChildBaseData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 5,
            ptr: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.ptr = Vec::with_capacity(count);

        self.count = count;
        self.n_vars = std::cmp::max(
            self.count.next_power_of_two().trailing_zeros() as usize,
            U::LOG_BITS + 3, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data) {
        self.ptr.push(mpt_state.mem.to_mult(data.ptr));

        self.index += 1;
    }
    #[instrument(
        name = "get_child_base",
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
        builder.push_namespace("get_child_base");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let ptr = builder.add_committed("ptr", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            (
                self.ptr,
                witness.new_column::<B32>(ptr).as_mut_slice::<B32>(),
            )
                .into_par_iter()
                .for_each(|(ptr, ptr_col)| {
                    *ptr_col = ptr;
                })
        }

        // from get_child pull (ptr, 1, ptr)
        {
            let block0 = builder.add_linear_combination_with_offset(
                "flush 0, block 0",
                n_vars,
                B8::ONE * basis(32, 1),
                [(ptr, basis(32, 0)), (ptr, basis(32, 2))],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(ptr)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, ptr)| {
                        *block = (*ptr as u128) << 64 | 1 << 32 | (*ptr as u128);
                    });
            }

            builder.receive(channel_ids.get_child, count, [block0]);
        }

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    pub(crate) fn get_child_base(&mut self, action: Action, ptr: u32) -> u32 {
        match action {
            Action::Append => self
                .get_child_base_table
                .append(&mut self.state, GetChildBaseData { ptr }),
            Action::Count => self.get_child_base_count += 1,
            Action::Ignore => (),
        }
        ptr
    }
}

// RECURSIVE
pub(crate) struct GetChildRecursiveData {
    ptr: u32,
    val: u8,
    offset: u32,
    child_index: u8,
    new_ptr: u32,
    output: u32,
}
struct RecursiveRowMajors {
    ptr: B32,
    val: B8,
    ts: B32,
    offset: B32,
    offset_lookup_ts: B32,
    child_index: B8,
    new_ptr: B32,
    output: B32,
}
pub(crate) struct GetChildRecursiveTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    row_majors: Vec<RecursiveRowMajors>,
}
impl FunctionTable for GetChildRecursiveTable {
    type Data = GetChildRecursiveData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 3,
            row_majors: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
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
        self.row_majors.push(RecursiveRowMajors {
            ptr: mem.to_mult(data.ptr),
            val: B8::from_underlier(data.val),
            ts: mem.process_timestamp(data.ptr),
            offset: mem.to_mult(data.offset),
            offset_lookup_ts: mpt_state
                .get_child_offset_lookup
                .process_timestamp(data.val),
            child_index: U8_TO_MULT_MAP[data.child_index as usize],
            new_ptr: mem.to_mult(data.new_ptr),
            output: mem.to_mult(data.output),
        });
        self.index += 1;
    }
    #[instrument(
        name = "get_child_recursive",
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
        builder.push_namespace("get_child_recursive");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let ptr = builder.add_committed("ptr", n_vars, B32::TOWER_LEVEL);
        let val = builder.add_committed("val", n_vars, B8::TOWER_LEVEL);
        let ts = builder.add_committed("ts", n_vars, B32::TOWER_LEVEL);
        let offset = builder.add_committed("offset", n_vars, B32::TOWER_LEVEL);
        let offset_lookup_ts = builder.add_committed("offset_lookup_ts", n_vars, B32::TOWER_LEVEL);
        let new_ptr = builder.add_committed("new_ptr", n_vars, B32::TOWER_LEVEL);
        let output = builder.add_committed("output", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (ptr, B32),
                    (val, B8),
                    (offset, B32),
                    (new_ptr, B32),
                    (output, B32)
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [(ts, B32, B32::one()), (offset_lookup_ts, B32, B32::one())]
            );
        }
        // child_index and child_index_minus_one
        let child_index = builder.add_committed("child_index", n_vars, B8::TOWER_LEVEL);
        let child_index_minus_one = builder.add_linear_combination_with_offset(
            "child index minus one",
            n_vars,
            B128::one(),
            [(child_index, B128::one())],
        )?;
        if let Some(witness) = builder.witness() {
            (
                &self.row_majors,
                witness
                    .new_column_with_default::<B8>(child_index, B8::new(2))
                    .as_mut_slice::<B8>(),
                witness
                    .new_column_with_default::<B8>(child_index_minus_one, B8::new(2) - B8::one())
                    .as_mut_slice::<B8>(),
            )
                .into_par_iter()
                .for_each(|(row_majors, child_index, child_index_minus_one)| {
                    *child_index = row_majors.child_index;
                    *child_index_minus_one = *child_index - B8::one();
                });
        }

        // from get_child pull (ptr, index, output_ptr)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (ptr, basis(32, 0)),
                    (child_index, basis(32, 1)),
                    (output, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(ptr)?.as_slice::<u32>(),
                    witness.get::<B8>(child_index)?.as_slice::<u8>(),
                    witness.get::<B32>(output)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, ptr, child_index, output)| {
                        *block =
                            (*output as u128) << 64 | (*child_index as u128) << 32 | (*ptr as u128);
                    });
            }

            builder.receive(channel_ids.get_child, count, [block0]);
        }
        // mem reads
        {
            read_mem(builder, "val", ptr, val, ts, n_vars, count, channel_ids.mem)?;
        }
        // read from get_child_offset_lookup
        {
            let read_block = builder.add_linear_combination(
                "flush 1, read_block",
                n_vars,
                [
                    (val, basis(32, 0)),
                    (offset, basis(32, 1)),
                    (offset_lookup_ts, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness
                        .new_column::<B128>(read_block)
                        .as_mut_slice::<u128>(),
                    witness.get::<B8>(val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                    witness.get::<B32>(offset_lookup_ts)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, val, offset, offset_lookup_ts)| {
                        *block = (*offset_lookup_ts as u128) << 64
                            | (*offset as u128) << 32
                            | (*val as u128);
                    });
            }
            builder.receive(channel_ids.get_child_offset_lookup, count, [read_block]);

            let write_block = builder.add_linear_combination(
                "flush 1, write_block",
                n_vars,
                [
                    (val, basis(32, 0)),
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
                    witness.get::<B8>(val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                    witness.get::<B32>(offset_lookup_ts)?.as_slice::<B32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, val, offset, offset_lookup_ts)| {
                        let incremented_ts = (*offset_lookup_ts) * B32::MULTIPLICATIVE_GENERATOR;
                        *block = (incremented_ts.to_underlier() as u128) << 64
                            | (*offset as u128) << 32
                            | (*val as u128);
                    });
            }
            builder.send(channel_ids.get_child_offset_lookup, count, [write_block]);
        }
        // to get_child push (new_ptr, index / F8::g, output)
        {
            let inverse = B8::MULTIPLICATIVE_GENERATOR.pow([254u64]);
            let block0 = builder.add_linear_combination(
                "flush 2, block 0",
                n_vars,
                [
                    (new_ptr, basis(32, 0)),
                    (child_index, basis(32, 1) * inverse),
                    (output, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(new_ptr)?.as_slice::<u32>(),
                    witness.get::<B8>(child_index)?.as_slice::<B8>(),
                    witness.get::<B32>(output)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, new_ptr, child_index, output)| {
                        let decremented_child_index = (*child_index) * inverse;
                        *block = (*output as u128) << 64
                            | (decremented_child_index.to_underlier() as u128) << 32
                            | (*new_ptr as u128);
                    });
            }

            builder.send(channel_ids.get_child, count, [block0]);
        }
        // new_ptr == ptr * offset
        builder.assert_zero(
            [new_ptr, ptr, offset],
            binius_macros::arith_expr!([new_ptr, ptr, offset] = new_ptr - ptr * offset)
                .convert_field(),
        );
        // child_index != 0
        builder.assert_not_zero(child_index);
        // child_index != 1
        builder.assert_not_zero(child_index_minus_one);

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    pub(crate) fn get_child_recursive(&mut self, action: Action, ptr: u32, child_index: u8) -> u32 {
        let val = self.state.mem[ptr];
        let offset = GetChildOffsetLookup::query(val) as u32;
        let new_ptr = ptr + offset;
        let output = self.get_child(action, new_ptr, child_index - 1);
        match action {
            Action::Append => self.get_child_recursive_table.append(
                &mut self.state,
                GetChildRecursiveData {
                    ptr,
                    val,
                    offset,
                    child_index,
                    new_ptr,
                    output,
                },
            ),
            Action::Count => self.get_child_recursive_count += 1,
            Action::Ignore => (),
        }
        output
    }
}
