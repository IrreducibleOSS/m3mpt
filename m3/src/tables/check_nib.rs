// Copyright 2024 Irreducible Inc.

use super::*;

use std::array;

impl MPT {
    pub(crate) fn check_nib(
        &mut self,
        action: Action,
        target_ptr: NibPtr,
        key_ptr: NibPtr,
        nib_ptr: NibPtr,
    ) -> NibPtr {
        match nib_ptr == target_ptr {
            true => self.check_nib_base(action, target_ptr, key_ptr, nib_ptr),
            false => self.check_nib_recursive(action, target_ptr, key_ptr, nib_ptr),
        }
    }
}

pub(crate) struct CheckNibBaseData {
    nib_ptr: NibPtr,
    key_ptr: NibPtr,
}
pub(crate) struct CheckNibBaseTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    nib_ptr_byte: Vec<B32>,
    nib_ptr_parity: BitVec,
    key_ptr_byte: Vec<B32>,
    key_ptr_parity: BitVec,
}
impl FunctionTable for CheckNibBaseTable {
    type Data = CheckNibBaseData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 0,
            nib_ptr_byte: vec![],
            nib_ptr_parity: BitVec::new(None),
            key_ptr_byte: vec![],
            key_ptr_parity: BitVec::new(None),
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.nib_ptr_byte = Vec::with_capacity(count);
        self.nib_ptr_parity = BitVec::new(Some(count));
        self.key_ptr_byte = Vec::with_capacity(count);
        self.key_ptr_parity = BitVec::new(Some(count));

        self.count = count;
        self.n_vars = std::cmp::max(
            self.count.next_power_of_two().trailing_zeros() as usize,
            U::LOG_BITS + 3, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data) {
        let mem = &mut mpt_state.mem;

        self.nib_ptr_byte.push(mem.to_mult(data.nib_ptr.byte));
        self.nib_ptr_parity.push(data.nib_ptr.parity);
        self.key_ptr_byte.push(mem.to_mult(data.key_ptr.byte));
        self.key_ptr_parity.push(data.key_ptr.parity);

        self.index += 1;
    }
    #[instrument(
        name = "check_nib",
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
        builder.push_namespace("check_nib_base");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let nib_ptr_byte = builder.add_committed("nib_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let key_ptr_byte = builder.add_committed("key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.nib_ptr_byte,
                witness
                    .new_column::<B32>(nib_ptr_byte)
                    .as_mut_slice::<B32>(),
                self.key_ptr_byte,
                witness
                    .new_column::<B32>(key_ptr_byte)
                    .as_mut_slice::<B32>(),
            )
                .into_par_iter()
                .for_each(
                    |(nib_ptr_byte_src, nib_ptr_byte_dest, key_ptr_byte_src, key_ptr_byte_dest)| {
                        *nib_ptr_byte_dest = nib_ptr_byte_src;
                        *key_ptr_byte_dest = key_ptr_byte_src;
                    },
                )
        }

        let nib_ptr_parity = builder.add_committed("nib_ptr_parity", n_vars, B1::TOWER_LEVEL);
        let key_ptr_parity = builder.add_committed("key_ptr_parity", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.nib_ptr_parity,
                witness
                    .new_column::<B1>(nib_ptr_parity)
                    .as_mut_slice::<u8>(),
                self.key_ptr_parity,
                witness
                    .new_column::<B1>(key_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(
                    |(
                        source_byte_state_key,
                        dest_byte_state_key,
                        source_byte_new_key,
                        dest_byte_new_key,
                    )| {
                        *dest_byte_state_key = source_byte_state_key;
                        *dest_byte_new_key = source_byte_new_key;
                    },
                );
        }

        // from check_nib pull (nib_ptr_byte, key_ptr_byte, nib_ptr_byte, key_ptr_byte; nib_ptr_parity, key_ptr_parity, nib_ptr_parity, key_ptr_parity)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (nib_ptr_byte, basis(32, 0)),
                    (key_ptr_byte, basis(32, 1)),
                    (nib_ptr_byte, basis(32, 2)),
                    (key_ptr_byte, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(nib_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(key_ptr_byte)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, nib_ptr_byte, key_ptr_byte)| {
                        *block = (*key_ptr_byte as u128) << 96
                            | (*nib_ptr_byte as u128) << 64
                            | (*key_ptr_byte as u128) << 32
                            | (*nib_ptr_byte as u128);
                    });
            }

            let block1 = builder.add_linear_combination(
                "flush 0, block 1",
                n_vars,
                [
                    (nib_ptr_parity, basis(32, 0)),
                    (key_ptr_parity, basis(32, 1)),
                    (nib_ptr_parity, basis(32, 2)),
                    (key_ptr_parity, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let nib_ptr_bit_iter =
                    BitIterator::new(witness.get::<B1>(nib_ptr_parity)?.as_slice::<u8>(), None);

                let key_ptr_bit_iter =
                    BitIterator::new(witness.get::<B1>(key_ptr_parity)?.as_slice::<u8>(), None);

                izip!(
                    witness.new_column::<B128>(block1).as_mut_slice::<u128>(),
                    nib_ptr_bit_iter,
                    key_ptr_bit_iter
                )
                .for_each(|(block, nib_ptr_parity, key_ptr_parity)| {
                    let nib_ptr = match nib_ptr_parity {
                        true => 1,
                        false => 0,
                    };
                    let key_ptr = match key_ptr_parity {
                        true => 1,
                        false => 0,
                    };
                    *block = (key_ptr as u128) << 96
                        | (nib_ptr as u128) << 64
                        | (key_ptr as u128) << 32
                        | (nib_ptr as u128);
                });
            }

            builder.receive(channel_ids.check_nib, count, [block0, block1]);
        }

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    fn check_nib_base(
        &mut self,
        action: Action,
        target_ptr: NibPtr,
        key_ptr: NibPtr,
        nib_ptr: NibPtr,
    ) -> NibPtr {
        assert_eq!(target_ptr, nib_ptr);
        match action {
            Action::Append => self
                .check_nib_base_table
                .append(&mut self.state, CheckNibBaseData { nib_ptr, key_ptr }),
            Action::Count => self.check_nib_base_count += 1,
            Action::Ignore => (),
        }
        key_ptr
    }
}

pub(crate) struct CheckNibRecursiveData {
    target_ptr: NibPtr,
    nib_val: u8,
    nib_ptr: NibPtr,
    new_nib_ptr: NibPtr,
    key_val: u8,
    key_ptr: NibPtr,
    new_key_ptr: NibPtr,
    return_ptr: NibPtr,
}

struct ColumnMajors {
    target_ptr_parity: BitVec,
    nib_val_bits: [BitVec; 8],
    nib_ptr_parity: BitVec,
    key_val_bits: [BitVec; 8],
    key_ptr_parity: BitVec,
    return_ptr_parity: BitVec,
}

struct RowMajors {
    target_ptr_byte: B32,
    nib_ts: B32,
    nib_ptr_byte: B32,
    new_nib_ptr_byte: B32,
    key_ts: B32,
    key_ptr_byte: B32,
    new_key_ptr_byte: B32,
    return_ptr_byte: B32,
}

pub(crate) struct CheckNibRecursiveTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    col_majors: ColumnMajors,
    row_majors: Vec<RowMajors>,
}
impl FunctionTable for CheckNibRecursiveTable {
    type Data = CheckNibRecursiveData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 0,
            col_majors: ColumnMajors {
                target_ptr_parity: BitVec::new(None),
                nib_val_bits: array::from_fn(|_| BitVec::new(None)),
                nib_ptr_parity: BitVec::new(None),
                key_val_bits: array::from_fn(|_| BitVec::new(None)),
                key_ptr_parity: BitVec::new(None),
                return_ptr_parity: BitVec::new(None),
            },
            row_majors: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.col_majors = ColumnMajors {
            target_ptr_parity: BitVec::new(Some(count)),
            nib_val_bits: std::array::from_fn(|_| BitVec::new(Some(count))),
            nib_ptr_parity: BitVec::new(Some(count)),
            key_val_bits: std::array::from_fn(|_| BitVec::new(Some(count))),
            key_ptr_parity: BitVec::new(Some(count)),
            return_ptr_parity: BitVec::new(Some(count)),
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
        self.col_majors
            .target_ptr_parity
            .push(data.target_ptr.parity);
        (0..8).for_each(|i| {
            self.col_majors.nib_val_bits[i].push(data.nib_val & (1 << i) == (1 << i));
            self.col_majors.key_val_bits[i].push(data.key_val & (1 << i) == (1 << i));
        });
        self.col_majors.nib_ptr_parity.push(data.nib_ptr.parity);
        self.col_majors.key_ptr_parity.push(data.key_ptr.parity);
        self.col_majors
            .return_ptr_parity
            .push(data.return_ptr.parity);

        let mem = &mut mpt_state.mem;
        self.row_majors.push(RowMajors {
            target_ptr_byte: mem.to_mult(data.target_ptr.byte),
            nib_ts: mem.process_timestamp(data.nib_ptr.byte),
            nib_ptr_byte: mem.to_mult(data.nib_ptr.byte),
            key_ts: mem.process_timestamp(data.key_ptr.byte),
            new_nib_ptr_byte: mem.to_mult(data.new_nib_ptr.byte),
            key_ptr_byte: mem.to_mult(data.key_ptr.byte),
            new_key_ptr_byte: mem.to_mult(data.new_key_ptr.byte),
            return_ptr_byte: mem.to_mult(data.return_ptr.byte),
        });

        self.index += 1;
    }
    #[instrument(
        name = "check_nib_recursive",
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
        builder.push_namespace("check_nib_recursive");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let target_ptr_byte = builder.add_committed("target_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let key_ptr_byte = builder.add_committed("key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let key_ts = builder.add_committed("key_ts", n_vars, B32::TOWER_LEVEL);
        let new_key_ptr_byte = builder.add_committed("new_key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let nib_ptr_byte = builder.add_committed("nib_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let nib_ts = builder.add_committed("nib_ts", n_vars, B32::TOWER_LEVEL);
        let new_nib_ptr_byte = builder.add_committed("new_nib_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let return_ptr_byte = builder.add_committed("return_ptr_byte", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (target_ptr_byte, B32),
                    (key_ptr_byte, B32),
                    (new_key_ptr_byte, B32),
                    (nib_ptr_byte, B32),
                    (new_nib_ptr_byte, B32),
                    (return_ptr_byte, B32),
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [(nib_ts, B32, B32::one()), (key_ts, B32, B32::one())]
            );
        }

        let target_ptr_parity = builder.add_committed("target_ptr_parity", n_vars, B1::TOWER_LEVEL);
        let nib_ptr_parity = builder.add_committed("nib_ptr_parity", n_vars, B1::TOWER_LEVEL);
        let key_ptr_parity = builder.add_committed("key_ptr_parity", n_vars, B1::TOWER_LEVEL);
        let return_ptr_parity = builder.add_committed("return_ptr_parity", n_vars, B1::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            (
                self.col_majors.target_ptr_parity,
                witness
                    .new_column::<B1>(target_ptr_parity)
                    .as_mut_slice::<u8>(),
                self.col_majors.nib_ptr_parity,
                witness
                    .new_column::<B1>(nib_ptr_parity)
                    .as_mut_slice::<u8>(),
                self.col_majors.key_ptr_parity,
                witness
                    .new_column::<B1>(key_ptr_parity)
                    .as_mut_slice::<u8>(),
                self.col_majors.return_ptr_parity,
                witness
                    .new_column::<B1>(return_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(|(src1, dest1, src2, dest2, src3, dest3, src4, dest4)| {
                    *dest1 = src1;
                    *dest2 = src2;
                    *dest3 = src3;
                    *dest4 = src4;
                });
        }

        let nib_val_bits =
            builder.add_committed_multiple::<8>("nib_val_bits", n_vars, B1::TOWER_LEVEL);
        let key_val_bits =
            builder.add_committed_multiple::<8>("key_val_bits", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            izip!(nib_val_bits, self.col_majors.nib_val_bits).for_each(|(id, bit_vec)| {
                (bit_vec, witness.new_column::<B1>(id).as_mut_slice::<u8>())
                    .into_par_iter()
                    .for_each(|(src, dest)| {
                        *dest = src;
                    })
            });
            izip!(key_val_bits, self.col_majors.key_val_bits).for_each(|(id, bit_vec)| {
                (bit_vec, witness.new_column::<B1>(id).as_mut_slice::<u8>())
                    .into_par_iter()
                    .for_each(|(src, dest)| {
                        *dest = src;
                    })
            });
        }

        // from check_nib pull (target_ptr_byte_id, key_ptr_byte, nib_ptr_byte, return_ptr_byte; target_ptr_parity, key_ptr_parity, nib_ptr_parity, return_ptr_parity)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (target_ptr_byte, basis(32, 0)),
                    (key_ptr_byte, basis(32, 1)),
                    (nib_ptr_byte, basis(32, 2)),
                    (return_ptr_byte, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(target_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(nib_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(return_ptr_byte)?.as_slice::<u32>(),
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
                    (target_ptr_parity, basis(32, 0)),
                    (key_ptr_parity, basis(32, 1)),
                    (nib_ptr_parity, basis(32, 2)),
                    (return_ptr_parity, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                izip!(
                    witness.new_column::<B128>(block1).as_mut_slice::<u128>(),
                    BitIterator::new(witness.get::<B1>(target_ptr_parity)?.as_slice::<u8>(), None),
                    BitIterator::new(witness.get::<B1>(key_ptr_parity)?.as_slice::<u8>(), None),
                    BitIterator::new(witness.get::<B1>(nib_ptr_parity)?.as_slice::<u8>(), None),
                    BitIterator::new(witness.get::<B1>(return_ptr_parity)?.as_slice::<u8>(), None)
                )
                .for_each(|(block, a, b, c, d)| {
                    fn parity_to_num(parity: bool) -> u128 {
                        match parity {
                            true => 1,
                            false => 0,
                        }
                    }
                    *block = parity_to_num(d) << 96
                        | parity_to_num(c) << 64
                        | parity_to_num(b) << 32
                        | parity_to_num(a);
                });
            }

            builder.receive(channel_ids.check_nib, count, [block0, block1]);
        }
        // low and high key_val nibbles
        let low_key_val_nib = builder.add_linear_combination(
            "low_key_val_nib",
            n_vars,
            [
                (key_val_bits[0], basis(1, 0)),
                (key_val_bits[1], basis(1, 1)),
                (key_val_bits[2], basis(1, 2)),
                (key_val_bits[3], basis(1, 3)),
            ],
        )?;
        if let Some(witness) = builder.witness() {
            izip!(
                witness
                    .new_column::<B8>(low_key_val_nib)
                    .as_mut_slice::<u8>(),
                BitIterator::new(witness.get::<B1>(key_val_bits[0])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[1])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[2])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[3])?.as_slice::<u8>(), None),
            )
            .for_each(|(block, a, b, c, d)| {
                fn parity_to_num(parity: bool) -> u8 {
                    match parity {
                        true => 1,
                        false => 0,
                    }
                }
                *block = parity_to_num(d) << 3
                    | parity_to_num(c) << 2
                    | parity_to_num(b) << 1
                    | parity_to_num(a)
            });
        }

        let high_key_val_nib = builder.add_linear_combination(
            "high_key_val_nib",
            n_vars,
            [
                (key_val_bits[4], basis(1, 0)),
                (key_val_bits[5], basis(1, 1)),
                (key_val_bits[6], basis(1, 2)),
                (key_val_bits[7], basis(1, 3)),
            ],
        )?;
        if let Some(witness) = builder.witness() {
            izip!(
                witness
                    .new_column::<B8>(high_key_val_nib)
                    .as_mut_slice::<u8>(),
                BitIterator::new(witness.get::<B1>(key_val_bits[4])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[5])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[6])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(key_val_bits[7])?.as_slice::<u8>(), None),
            )
            .for_each(|(block, a, b, c, d)| {
                fn parity_to_num(parity: bool) -> u8 {
                    match parity {
                        true => 1,
                        false => 0,
                    }
                }
                *block = parity_to_num(d) << 3
                    | parity_to_num(c) << 2
                    | parity_to_num(b) << 1
                    | parity_to_num(a)
            });
        }

        // low and high nib_val nibbles
        let low_nib_val_nib = builder.add_linear_combination(
            "low_key_val_nib",
            n_vars,
            [
                (nib_val_bits[0], basis(1, 0)),
                (nib_val_bits[1], basis(1, 1)),
                (nib_val_bits[2], basis(1, 2)),
                (nib_val_bits[3], basis(1, 3)),
            ],
        )?;
        if let Some(witness) = builder.witness() {
            izip!(
                witness
                    .new_column::<B8>(low_nib_val_nib)
                    .as_mut_slice::<u8>(),
                BitIterator::new(witness.get::<B1>(nib_val_bits[0])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[1])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[2])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[3])?.as_slice::<u8>(), None),
            )
            .for_each(|(block, a, b, c, d)| {
                fn parity_to_num(parity: bool) -> u8 {
                    match parity {
                        true => 1,
                        false => 0,
                    }
                }
                *block = parity_to_num(d) << 3
                    | parity_to_num(c) << 2
                    | parity_to_num(b) << 1
                    | parity_to_num(a)
            });
        }

        let high_nib_val_nib = builder.add_linear_combination(
            "high_key_val_nib",
            n_vars,
            [
                (nib_val_bits[4], basis(1, 0)),
                (nib_val_bits[5], basis(1, 1)),
                (nib_val_bits[6], basis(1, 2)),
                (nib_val_bits[7], basis(1, 3)),
            ],
        )?;
        if let Some(witness) = builder.witness() {
            izip!(
                witness
                    .new_column::<B8>(high_nib_val_nib)
                    .as_mut_slice::<u8>(),
                BitIterator::new(witness.get::<B1>(nib_val_bits[4])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[5])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[6])?.as_slice::<u8>(), None),
                BitIterator::new(witness.get::<B1>(nib_val_bits[7])?.as_slice::<u8>(), None),
            )
            .for_each(|(block, a, b, c, d)| {
                fn parity_to_num(parity: bool) -> u8 {
                    match parity {
                        true => 1,
                        false => 0,
                    }
                }
                *block = parity_to_num(d) << 3
                    | parity_to_num(c) << 2
                    | parity_to_num(b) << 1
                    | parity_to_num(a)
            });
        }
        // mem reads
        {
            read_mem_with_nibbles(
                builder,
                "key_val",
                key_ptr_byte,
                low_key_val_nib,
                high_key_val_nib,
                key_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
            read_mem_with_nibbles(
                builder,
                "nib_val",
                nib_ptr_byte,
                low_nib_val_nib,
                high_nib_val_nib,
                nib_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
        }
        // to check_nib push (target_ptr_byte, new_key_ptr_byte, new_nib_ptr_byte, return_ptr_byte, target_ptr_parity, new_key_ptr_parity, new_nib_ptr_parity, return_ptr_parity)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (target_ptr_byte, basis(32, 0)),
                    (new_key_ptr_byte, basis(32, 1)),
                    (new_nib_ptr_byte, basis(32, 2)),
                    (return_ptr_byte, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(target_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(new_key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(new_nib_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(return_ptr_byte)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, a, b, c, d)| {
                        *block = (*d as u128) << 96
                            | (*c as u128) << 64
                            | (*b as u128) << 32
                            | (*a as u128);
                    });
            }

            let block1 = builder.add_linear_combination_with_offset(
                "flush 0, block 1",
                n_vars,
                basis(32, 1) + basis(32, 2),
                [
                    (target_ptr_parity, basis(32, 0)),
                    (key_ptr_parity, basis(32, 1)),
                    (nib_ptr_parity, basis(32, 2)),
                    (return_ptr_parity, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let target_ptr_parity_iter =
                    BitIterator::new(witness.get::<B1>(target_ptr_parity)?.as_slice::<u8>(), None);

                let key_ptr_parity_iter =
                    BitIterator::new(witness.get::<B1>(key_ptr_parity)?.as_slice::<u8>(), None);

                let nib_ptr_parity_iter =
                    BitIterator::new(witness.get::<B1>(nib_ptr_parity)?.as_slice::<u8>(), None);

                let return_ptr_parity_iter =
                    BitIterator::new(witness.get::<B1>(return_ptr_parity)?.as_slice::<u8>(), None);

                izip!(
                    witness.new_column::<B128>(block1).as_mut_slice::<u128>(),
                    target_ptr_parity_iter,
                    key_ptr_parity_iter,
                    nib_ptr_parity_iter,
                    return_ptr_parity_iter
                )
                .for_each(|(block, a, b, c, d)| {
                    fn parity_to_num(parity: bool) -> u128 {
                        match parity {
                            true => 1,
                            false => 0,
                        }
                    }
                    *block = parity_to_num(d) << 96
                        | parity_to_num(!c) << 64
                        | parity_to_num(!b) << 32
                        | parity_to_num(a);
                });
            }

            builder.send(channel_ids.check_nib, count, [block0, block1]);
        }

        // new_key_ptr_byte == key_ptr_parity * key_ptr_byte * g + (1-key_ptr_parity) * key_ptr_byte
        {
            let g_expr = ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR);
            let composition = {
                let new_key_ptr_byte = ArithExpr::Var(0);
                let key_ptr_byte = ArithExpr::Var(1);
                let key_ptr_parity = ArithExpr::Var(2);
                new_key_ptr_byte
                    + key_ptr_parity.clone() * key_ptr_byte.clone() * g_expr
                    + (ArithExpr::one() - key_ptr_parity) * key_ptr_byte
            };
            builder.assert_zero(
                [new_key_ptr_byte, key_ptr_byte, key_ptr_parity],
                composition.convert_field(),
            )
        };

        // new_nib_ptr_byte == nib_ptr_parity * nib_ptr_byte * g + (1-nib_ptr_parity) * nib_ptr_byte
        {
            let g_expr = ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR);
            let composition = {
                let new_nib_ptr_byte = ArithExpr::Var(0);
                let nib_ptr_byte = ArithExpr::Var(1);
                let nib_ptr_parity = ArithExpr::Var(2);
                new_nib_ptr_byte
                    + nib_ptr_parity.clone() * nib_ptr_byte.clone() * g_expr
                    + (ArithExpr::one() - nib_ptr_parity) * nib_ptr_byte
            };
            builder.assert_zero(
                [new_nib_ptr_byte, nib_ptr_byte, nib_ptr_parity],
                composition.convert_field(),
            );
        }

        // key_nib == nib_nib
        {
            builder.assert_zero(
                [
                    key_ptr_parity,
                    high_key_val_nib,
                    low_key_val_nib,
                    nib_ptr_parity,
                    low_nib_val_nib,
                    high_nib_val_nib,
                ],
                binius_macros::arith_expr!(
                    [
                        key_ptr_parity,
                        high_key_val_nib,
                        low_key_val_nib,
                        nib_ptr_parity,
                        low_nib_val_nib,
                        high_nib_val_nib
                    ] = (key_ptr_parity * low_key_val_nib
                        + (1 - key_ptr_parity) * high_key_val_nib)
                        - (nib_ptr_parity * low_nib_val_nib
                            + (1 - nib_ptr_parity) * high_nib_val_nib)
                )
                .convert_field(),
            );
        }

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    fn check_nib_recursive(
        &mut self,
        action: Action,
        target_ptr: NibPtr,
        key_ptr: NibPtr,
        nib_ptr: NibPtr,
    ) -> NibPtr {
        assert!(target_ptr != nib_ptr);

        let key_val = self.state.mem[key_ptr.byte];
        let nib_val = self.state.mem[nib_ptr.byte];
        {
            let key_shift = match key_ptr.parity {
                true => 0,
                false => 4,
            };
            let key_nib = (key_val >> key_shift) & 0x0f;
            let nib_shift = match nib_ptr.parity {
                true => 0,
                false => 4,
            };
            let nib_nib = (nib_val >> nib_shift) & 0x0f;
            assert_eq!(key_nib, nib_nib);
        }

        let new_key_ptr = MPT::increment(key_ptr);
        let new_nib_ptr = MPT::increment(nib_ptr);
        let return_ptr = self.check_nib(action, target_ptr, new_key_ptr, new_nib_ptr);
        match action {
            Action::Append => self.check_nib_recursive_table.append(
                &mut self.state,
                CheckNibRecursiveData {
                    target_ptr,
                    nib_val,
                    nib_ptr,
                    new_nib_ptr,
                    key_val,
                    key_ptr,
                    new_key_ptr,
                    return_ptr,
                },
            ),
            Action::Count => self.check_nib_recursive_count += 1,
            Action::Ignore => (),
        }
        return_ptr
    }
}
