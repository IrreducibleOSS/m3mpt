// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct ExtLeafTransAdvice {
    state: State,
    first_child_ptr: u32,
    first_child_val: u8,
    bytes_ptr: u32,
    bytes_ptr_val: u8,
    nib_ptr: NibPtr,
    post_bytes_ptr: u32,
    new_key_ptr: NibPtr,
}

struct ColMajors {
    state_key_ptr_parity: BitVec,
    new_key_ptr_parity: BitVec,
    first_child_val_bits: [BitVec; 8],
    bytes_ptr_val_bits: [BitVec; 8],
}

struct RowMajors {
    state_start_ptr: B32,
    state_key_ptr_byte: B32,
    state_rlp_ptr: B32,
    state_ts: B32,
    first_child_ptr: B32,
    first_child_val: B8,
    first_child_ts: B32,
    bytes_ptr: B32,
    bytes_ptr_val: B8,
    bytes_ptr_ts: B32,
    post_bytes_ptr: B32,
    new_key_ptr_byte: B32,
    nib_ptr_byte: B32,
    g_raised_to_first_three_first_child_bits: B32,
    g_raised_to_next_four_first_child_bits: B32,
}
pub(crate) struct ExtLeafTransTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    col_majors: ColMajors,
    row_majors: Vec<RowMajors>,
}

impl FunctionTable for ExtLeafTransTable {
    type Data = ExtLeafTransAdvice;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 0,
            col_majors: ColMajors {
                state_key_ptr_parity: BitVec::new(None),
                new_key_ptr_parity: BitVec::new(None),
                first_child_val_bits: std::array::from_fn(|_| BitVec::new(None)),
                bytes_ptr_val_bits: std::array::from_fn(|_| BitVec::new(None)),
            },
            row_majors: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.row_majors = Vec::with_capacity(count);

        self.col_majors.state_key_ptr_parity = BitVec::new(Some(count));
        self.col_majors.new_key_ptr_parity = BitVec::new(Some(count));
        self.col_majors.first_child_val_bits = std::array::from_fn(|_| BitVec::new(Some(count)));
        self.col_majors.bytes_ptr_val_bits = std::array::from_fn(|_| BitVec::new(Some(count)));

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
        self.col_majors
            .first_child_val_bits
            .iter_mut()
            .enumerate()
            .for_each(|(i, bit_vec)| {
                bit_vec.push(data.first_child_val & (1 << i) == 1 << i);
            });
        self.col_majors
            .bytes_ptr_val_bits
            .iter_mut()
            .enumerate()
            .for_each(|(i, bit_vec)| {
                bit_vec.push(data.bytes_ptr_val & (1 << i) == 1 << i);
            });

        let mut g_powers = std::iter::successors(Some(B32::MULTIPLICATIVE_GENERATOR), |&prev| {
            Some(prev * prev)
        })
        .take(7);

        let g_raised_to_first_three_first_child_bits =
            g_powers
                .by_ref()
                .take(3)
                .enumerate()
                .fold(B32::ONE, |acc, (i, g_power)| {
                    let first_child_bit = match data.first_child_val & (1 << i) == 1 << i {
                        true => B1::one(),
                        false => B1::zero(),
                    };
                    acc * (first_child_bit * g_power + (B32::one() - first_child_bit))
                });

        let g_raised_to_next_four_first_child_bits =
            g_powers
                .by_ref()
                .take(4)
                .enumerate()
                .fold(B32::ONE, |acc, (i, g_power)| {
                    let first_child_bit =
                        match data.first_child_val & (1 << (3 + i)) == 1 << (3 + i) {
                            true => B1::one(),
                            false => B1::zero(),
                        };
                    acc * (first_child_bit * g_power + (B32::one() - first_child_bit))
                });

        self.row_majors.push(RowMajors {
            state_start_ptr: mem.to_mult(data.state.start_ptr),
            state_key_ptr_byte: mem.to_mult(data.state.key_ptr.byte),
            state_rlp_ptr: mem.to_mult(data.state.rlp_ptr),
            state_ts: data.state.ts,
            post_bytes_ptr: mem.to_mult(data.post_bytes_ptr),
            new_key_ptr_byte: mem.to_mult(data.new_key_ptr.byte),
            first_child_ptr: mem.to_mult(data.first_child_ptr),
            first_child_val: B8::from_underlier(data.first_child_val),
            first_child_ts: mem.process_timestamp(data.first_child_ptr),
            bytes_ptr: mem.to_mult(data.bytes_ptr),
            bytes_ptr_val: B8::from_underlier(data.bytes_ptr_val),
            bytes_ptr_ts: mem.process_timestamp(data.bytes_ptr),
            nib_ptr_byte: mem.to_mult(data.nib_ptr.byte),
            // this should hold
            g_raised_to_first_three_first_child_bits,
            g_raised_to_next_four_first_child_bits,
        });

        self.index += 1;
    }
    #[instrument(
        name = "ext_leaf_trans",
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
        builder.push_namespace("ext_leaf_trans");
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
        let post_bytes_ptr = builder.add_committed("post_bytes_ptr", n_vars, B32::TOWER_LEVEL);
        let new_key_ptr_byte = builder.add_committed("new_key_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let first_child_ptr = builder.add_committed("first_child_ptr", n_vars, B32::TOWER_LEVEL);
        let first_child_val = builder.add_committed("first_child_val", n_vars, B8::TOWER_LEVEL);
        let first_child_ts = builder.add_committed("first_child_ts", n_vars, B32::TOWER_LEVEL);
        let bytes_ptr = builder.add_committed("bytes_ptr", n_vars, B32::TOWER_LEVEL);
        let bytes_ptr_val = builder.add_committed("bytes_ptr_val", n_vars, B8::TOWER_LEVEL);
        let bytes_ptr_ts = builder.add_committed("bytes_ptr_ts", n_vars, B32::TOWER_LEVEL);
        let nib_ptr_byte = builder.add_committed("nib_ptr_byte", n_vars, B32::TOWER_LEVEL);
        let g_raised_to_first_three_first_child_bits = builder.add_committed(
            "g_raised_to_first_three_first_child_bits",
            n_vars,
            B32::TOWER_LEVEL,
        );
        let g_raised_to_next_four_first_child_bits = builder.add_committed(
            "g_raised_to_next_four_first_child_bits",
            n_vars,
            B32::TOWER_LEVEL,
        );

        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [
                    (state_start_ptr, B32),
                    (state_key_ptr_byte, B32),
                    (state_rlp_ptr, B32),
                    (post_bytes_ptr, B32),
                    (new_key_ptr_byte, B32),
                    (nib_ptr_byte, B32),
                    (first_child_ptr, B32),
                    (first_child_val, B8),
                    (bytes_ptr, B32),
                    (bytes_ptr_val, B8),
                ]
            );
            populate_committed_polys_with_default!(
                par_data_iter,
                witness,
                [
                    (first_child_ts, B32, B32::one()),
                    (state_ts, B32, B32::one()),
                    (bytes_ptr_ts, B32, B32::one()),
                    (g_raised_to_first_three_first_child_bits, B32, B32::one()),
                    (g_raised_to_next_four_first_child_bits, B32, B32::one())
                ]
            );
        }

        let state_key_ptr_parity =
            builder.add_committed("state_key_parity_ptr", n_vars, B1::TOWER_LEVEL);
        let new_key_ptr_parity =
            builder.add_committed("new_key_parity_ptr", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            (
                self.col_majors.state_key_ptr_parity,
                witness
                    .new_column::<B1>(state_key_ptr_parity)
                    .as_mut_slice::<u8>(),
                self.col_majors.new_key_ptr_parity,
                witness
                    .new_column::<B1>(new_key_ptr_parity)
                    .as_mut_slice::<u8>(),
            )
                .into_par_iter()
                .for_each(|(src1, dest1, src2, dest2)| {
                    *dest1 = src1;
                    *dest2 = src2;
                });
        }

        let first_child_val_bits =
            builder.add_committed_multiple::<8>("first_child_vals_bits", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            izip!(first_child_val_bits, self.col_majors.first_child_val_bits).for_each(
                |(id, bit_vec)| {
                    (bit_vec, witness.new_column::<B1>(id).as_mut_slice::<u8>())
                        .into_par_iter()
                        .for_each(|(src, dest)| {
                            *dest = src;
                        })
                },
            );
        }

        let bytes_ptr_val_bits =
            builder.add_committed_multiple::<8>("bytes_ptr_vals_bits", n_vars, B1::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            izip!(bytes_ptr_val_bits, self.col_majors.bytes_ptr_val_bits).for_each(
                |(id, bit_vec)| {
                    (bit_vec, witness.new_column::<B1>(id).as_mut_slice::<u8>())
                        .into_par_iter()
                        .for_each(|(src, dest)| {
                            *dest = src;
                        })
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
        // read first_child_val from mem
        {
            // check agreement between first_child_val and first_child_val_bits
            builder.assert_zero(
                [
                    first_child_val,
                    first_child_val_bits[0],
                    first_child_val_bits[1],
                    first_child_val_bits[2],
                    first_child_val_bits[3],
                    first_child_val_bits[4],
                    first_child_val_bits[5],
                    first_child_val_bits[6],
                    first_child_val_bits[7],
                ],
                binius_macros::arith_expr!(
                    B8[val, b0, b1, b2, b3, b4, b5, b6, b7] =
                        b0 * 1 + b1 * 2 + b2 * 4 + b3 * 8 + b4 * 16 + b5 * 32 + b6 * 64 + b7 * 128
                            - val
                )
                .convert_field(),
            );

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
        }
        // read bytes_ptr_val from mem
        {
            // check agreement between bytes_ptr_val and bytes_ptr_val_bits
            builder.assert_zero(
                [
                    bytes_ptr_val,
                    bytes_ptr_val_bits[0],
                    bytes_ptr_val_bits[1],
                    bytes_ptr_val_bits[2],
                    bytes_ptr_val_bits[3],
                    bytes_ptr_val_bits[4],
                    bytes_ptr_val_bits[5],
                    bytes_ptr_val_bits[6],
                    bytes_ptr_val_bits[7],
                ],
                binius_macros::arith_expr!(
                    B8[val, b0, b1, b2, b3, b4, b5, b6, b7] =
                        b0 * 1 + b1 * 2 + b2 * 4 + b3 * 8 + b4 * 16 + b5 * 32 + b6 * 64 + b7 * 128
                            - val
                )
                .convert_field(),
            );

            read_mem(
                builder,
                "bytes_ptr_val",
                bytes_ptr,
                bytes_ptr_val,
                bytes_ptr_ts,
                n_vars,
                count,
                channel_ids.mem,
            )?;
        }
        // to check_nib push (post_bytes_ptr, state_key_ptr_byte, nib_ptr_byte, new_key_ptr_byte, false, state_key_ptr_parity, nib_ptr_parity, new_key_ptr_parity)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (post_bytes_ptr, basis(32, 0)),
                    (state_key_ptr_byte, basis(32, 1)),
                    (nib_ptr_byte, basis(32, 2)),
                    (new_key_ptr_byte, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(post_bytes_ptr)?.as_slice::<u32>(),
                    witness.get::<B32>(state_key_ptr_byte)?.as_slice::<u32>(),
                    witness.get::<B32>(nib_ptr_byte)?.as_slice::<u32>(),
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
                    (state_key_ptr_parity, basis(32, 1)),
                    (bytes_ptr_val_bits[4], basis(32, 2)),
                    (new_key_ptr_parity, basis(32, 3)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let a_iter = BitIterator::new(
                    witness.get::<B1>(state_key_ptr_parity)?.as_slice::<u8>(),
                    None,
                );

                let b_iter = BitIterator::new(
                    witness.get::<B1>(bytes_ptr_val_bits[4])?.as_slice::<u8>(),
                    None,
                );

                let c_iter = BitIterator::new(
                    witness.get::<B1>(new_key_ptr_parity)?.as_slice::<u8>(),
                    None,
                );

                izip!(
                    witness.new_column::<B128>(block1).as_mut_slice::<u128>(),
                    a_iter,
                    b_iter,
                    c_iter
                )
                .for_each(|(block, a, b, c)| {
                    fn parity_to_num(parity: bool) -> u128 {
                        match parity {
                            true => 1,
                            false => 0,
                        }
                    }
                    *block =
                        parity_to_num(c) << 96 | parity_to_num(b) << 64 | parity_to_num(a) << 32;
                });
            }

            builder.send(channel_ids.check_nib, count, [block0, block1]);
        }

        // to state push (state_start_ptr, new_key_ptr_byte, post_bytes_ptr, state_ts; new_key_ptr_parity)
        {
            flush_state(
                builder,
                FlushDirection::Push,
                state_start_ptr,
                new_key_ptr_byte,
                post_bytes_ptr,
                state_ts,
                new_key_ptr_parity,
                n_vars,
                count,
                channel_ids.state,
            )?;
        }
        {
            // first_child_val != 0x80
            let first_child_val_minus_128 = builder.add_linear_combination_with_offset(
                "first_child_val_minus_128",
                n_vars,
                B128::from_underlier(0x80),
                [(first_child_val, B128::ONE)],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness
                        .new_column::<B8>(first_child_val_minus_128)
                        .as_mut_slice::<u8>(),
                    witness.get::<B8>(first_child_val)?.as_slice::<u8>(),
                )
                    .into_par_iter()
                    .for_each(|(block, first_child_val)| *block = (*first_child_val) ^ 0x80);
            }
            builder.assert_not_zero(first_child_val_minus_128);
        }
        // first_child_val != 0xa0
        {
            let first_child_val_minus_160 = builder.add_linear_combination_with_offset(
                "first_child_val_minus_160",
                n_vars,
                B128::from_underlier(0xa0),
                [(first_child_val, B128::ONE)],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness
                        .new_column::<B8>(first_child_val_minus_160)
                        .as_mut_slice::<u8>(),
                    witness.get::<B8>(first_child_val)?.as_slice::<u8>(),
                )
                    .into_par_iter()
                    .for_each(|(block, first_child_val)| *block = (*first_child_val) ^ 0xa0);
            }

            builder.assert_not_zero(first_child_val_minus_160);
        }
        // bytes_ptr == first_child_ptr * (first_child_val_bits[7] * g + (1 - first_child_val_bits[7]) * 1)
        {
            let arith = {
                let bytes_ptr = ArithExpr::Var(0);
                let first_child_ptr = ArithExpr::Var(1);
                let first_child_val_bits_7 = ArithExpr::Var(2);
                let sub_expr = first_child_val_bits_7.clone()
                    * ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR)
                    + (ArithExpr::one() - first_child_val_bits_7);
                bytes_ptr - first_child_ptr * sub_expr
            };
            builder.assert_zero(
                [bytes_ptr, first_child_ptr, first_child_val_bits[7]],
                arith.convert_field(),
            )
        }
        // check post_bytes_ptr == bytes_ptr * (first_child_val_bits[7] * g^first_child_val_without_seventh_bit + (1 - first_child_val_bits[7]))
        {
            let g_expr = ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR);
            let mut g_powers = std::iter::successors(Some(g_expr.clone()), |prev| {
                Some(prev.clone() * prev.clone())
            })
            .take(7);
            // check g_raised_to_first_three_first_child_bits
            {
                let g_raised_to_first_three_bits = g_powers.by_ref().take(3).enumerate().fold(
                    ArithExpr::one(),
                    |acc, (i, g_power)| {
                        acc * (ArithExpr::Var(i) * g_power + (ArithExpr::one() - ArithExpr::Var(i)))
                    },
                );
                builder.assert_zero(
                    [
                        first_child_val_bits[0],
                        first_child_val_bits[1],
                        first_child_val_bits[2],
                        g_raised_to_first_three_first_child_bits,
                    ],
                    (g_raised_to_first_three_bits - ArithExpr::Var(3)).convert_field(),
                );
            }
            // check g_raised_to_next_four_first_child_bits
            {
                let g_raised_to_next_four_bits = g_powers.by_ref().take(4).enumerate().fold(
                    ArithExpr::one(),
                    |acc, (i, g_power)| {
                        acc * (ArithExpr::Var(i) * g_power + (ArithExpr::one() - ArithExpr::Var(i)))
                    },
                );
                builder.assert_zero(
                    [
                        first_child_val_bits[3],
                        first_child_val_bits[4],
                        first_child_val_bits[5],
                        first_child_val_bits[6],
                        g_raised_to_next_four_first_child_bits,
                    ],
                    (g_raised_to_next_four_bits - ArithExpr::Var(4)).convert_field(),
                );
            }
            // check post_bytes_ptr ==  bytes_ptr * (first_child_val_bits[7] * g_raised_to_first_three_first_child_bits * g_raised_to_next_four_first_child_bits + (1 - first_child_val_bits[7]))
            {
                let arith = {
                    let post_bytes_ptr = ArithExpr::Var(0);
                    let bytes_ptr = ArithExpr::Var(1);
                    let first_child_val_seventh_bit = ArithExpr::Var(2);
                    let g_raised_to_first_three_first_child_bits = ArithExpr::Var(3);
                    let g_raised_to_next_four_first_child_bits = ArithExpr::Var(4);
                    let first_child_val_without_seventh_bit =
                        g_raised_to_first_three_first_child_bits
                            * g_raised_to_next_four_first_child_bits;
                    post_bytes_ptr
                        - bytes_ptr
                            * (first_child_val_seventh_bit.clone()
                                * first_child_val_without_seventh_bit
                                + (ArithExpr::one() - first_child_val_seventh_bit) * g_expr)
                };
                builder.assert_zero(
                    [
                        post_bytes_ptr,
                        bytes_ptr,
                        first_child_val_bits[7],
                        g_raised_to_first_three_first_child_bits,
                        g_raised_to_next_four_first_child_bits,
                    ],
                    arith.convert_field(),
                );
            }
        }
        // nib_ptr_byte == bytes_ptr * g^{1 - bytes_ptr_val_bits_ids[4]}
        {
            let arith = ArithExpr::Var(0)
                - ArithExpr::Var(1)
                    * ((ArithExpr::one() - ArithExpr::Var(2))
                        * ArithExpr::Const(B32::MULTIPLICATIVE_GENERATOR)
                        + ArithExpr::Var(2));
            builder.assert_zero(
                [nib_ptr_byte, bytes_ptr, bytes_ptr_val_bits[4]],
                arith.convert_field(),
            );
        }

        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    pub(crate) fn ext_leaf_trans(&mut self, action: Action, state: State) -> State {
        let first_child_ptr = self.skip_list_header(action, state.rlp_ptr);
        let first_child_val = self.state.mem[first_child_ptr];
        assert!(first_child_val != 0x80 && first_child_val != 0xa0);
        let bytes_ptr = first_child_ptr + ((first_child_val >> 7) & 0x01) as u32;
        let post_bytes_ptr = bytes_ptr
            + match first_child_val & 0x80 == 0x80 {
                true => first_child_val - 128,
                false => 1,
            } as u32;
        let bytes_ptr_val = self.state.mem[bytes_ptr];
        let is_odd = (bytes_ptr_val >> 4) & 0x01;
        let nib_ptr = NibPtr {
            byte: bytes_ptr + 1 - is_odd as u32,
            parity: is_odd == 0x01,
        };
        let new_key_ptr = self.check_nib(
            action,
            NibPtr {
                byte: post_bytes_ptr,
                parity: false,
            },
            state.key_ptr,
            nib_ptr,
        );
        let new_state = State {
            start_ptr: state.start_ptr,
            key_ptr: new_key_ptr,
            rlp_ptr: post_bytes_ptr,
            ts: state.ts,
        };
        match action {
            Action::Append => self.ext_leaf_trans_table.append(
                &mut self.state,
                ExtLeafTransAdvice {
                    state,
                    first_child_ptr,
                    first_child_val,
                    bytes_ptr,
                    bytes_ptr_val,
                    nib_ptr,
                    post_bytes_ptr,
                    new_key_ptr,
                },
            ),
            Action::Count => self.ext_leaf_trans_count += 1,
            Action::Ignore => (),
        }
        new_state
    }
}
