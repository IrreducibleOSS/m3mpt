// Copyright 2024 Irreducible Inc.

use super::*;

use std::array;

impl MPT {
    pub(crate) fn absorb_block(
        &mut self,
        action: Action,
        pre_hash_state: [u8; HASH_B],
        preimage_ptr: u32,
        hash_ptr: u32,
        blocks_left: u8,
    ) {
        match blocks_left == 0 {
            true => self.absorb_block_base(action, pre_hash_state, preimage_ptr, hash_ptr),
            false => self.absorb_block_recursive(
                action,
                pre_hash_state,
                preimage_ptr,
                hash_ptr,
                blocks_left,
            ),
        }
    }
}

// BASE
pub(crate) struct AbsorbBlockBaseData {
    pre_hash_state: [u8; HASH_B],
    preimage_ptr: u32,
    hash_ptr: u32,
}

struct BaseRowMajors {
    pre_hash_state: [B8; HASH_B],
    preimage_ptr: B32,
    hash_ptr: B32,
    read_tss: [B32; 32],
}

pub(crate) struct AbsorbBlockBaseTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    row_majors: Vec<BaseRowMajors>,
}
impl FunctionTable for AbsorbBlockBaseTable {
    type Data = AbsorbBlockBaseData;
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
            U::LOG_BITS + 2, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data) {
        self.row_majors.push(BaseRowMajors {
            pre_hash_state: array::from_fn(|i| B8::from_underlier(data.pre_hash_state[i])),
            preimage_ptr: mpt_state.mem.to_mult(data.preimage_ptr),
            hash_ptr: mpt_state.mem.to_mult(data.hash_ptr),
            read_tss: array::from_fn(|i| {
                mpt_state
                    .mem
                    .process_timestamp(data.hash_ptr + 1 + i as u32)
            }),
        });

        self.index += 1;
    }
    #[instrument(
        name = "absorb_block_base",
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
        builder.push_namespace("absorb_block_base");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let pre_hash_state =
            builder.add_committed_multiple::<HASH_B>("pre_hash_state", n_vars, B8::TOWER_LEVEL);
        let read_tss = builder.add_committed_multiple::<32>("read_tss", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let mut pre_hash_state_columns = pre_hash_state.map(|id| witness.new_column::<B8>(id));

            let pre_hash_state_slices = pre_hash_state_columns
                .each_mut()
                .map(|col| col.as_mut_slice::<B8>());

            let mut read_tss_columns =
                read_tss.map(|id| witness.new_column_with_default::<B32>(id, B32::one()));
            let read_tss_slices = read_tss_columns
                .each_mut()
                .map(move |col| col.as_mut_slice::<B32>());

            // figure out how to parallelize this
            for (i, row_majors) in self.row_majors.iter().enumerate() {
                for (j, value) in row_majors.pre_hash_state.iter().enumerate() {
                    pre_hash_state_slices[j][i] = *value;
                }
                for (j, value) in row_majors.read_tss.iter().enumerate() {
                    read_tss_slices[j][i] = *value;
                }
            }
        }

        let preimage_ptr = builder.add_committed("preimage_ptr", n_vars, B32::TOWER_LEVEL);
        let hash_ptr = builder.add_committed("hash_ptr", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [(preimage_ptr, B32), (hash_ptr, B32),]
            );
        }

        // from absorb_block pull (preimage_ptr, hash_ptr, pre_hash_state)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block_0",
                n_vars,
                [
                    (preimage_ptr, basis(32, 0)),
                    (hash_ptr, basis(32, 1)),
                    (pre_hash_state[0], basis(8, 8)),
                    (pre_hash_state[1], basis(8, 8 + 1)),
                    (pre_hash_state[2], basis(8, 8 + 2)),
                    (pre_hash_state[3], basis(8, 8 + 3)),
                    (pre_hash_state[4], basis(8, 8 + 4)),
                    (pre_hash_state[5], basis(8, 8 + 5)),
                    (pre_hash_state[6], basis(8, 8 + 6)),
                    (pre_hash_state[7], basis(8, 8 + 7)),
                ],
            )?;

            if let Some(witness) = builder.witness() {
                let mut block0_column = witness.new_column::<B128>(block0);
                let block0_u128 = block0_column.as_mut_slice::<u128>();

                block0_u128
                    .par_iter_mut()
                    .zip(&self.row_majors)
                    .for_each(|(dest, row_major)| {
                        let bytes = u64::from_le_bytes(array::from_fn(|j| {
                            row_major.pre_hash_state[j].to_underlier()
                        }));

                        *dest = (bytes as u128) << 64
                            | (row_major.hash_ptr.to_underlier() as u128) << 32
                            | (row_major.preimage_ptr.to_underlier() as u128);
                    });
            }

            let other_blocks: Vec<OracleId> = (0..12)
                .map(|i| {
                    let id = builder.add_linear_combination(
                        format!("flush 0, other_blocks_{}", i),
                        n_vars,
                        (0..16)
                            .map(|j| (pre_hash_state[8 + i * 16 + j], basis(8, j)))
                            .collect::<Vec<_>>(),
                    )?;
                    Ok(id)
                })
                .collect::<Result<_, anyhow::Error>>()?;

            if let Some(witness) = builder.witness() {
                for (i, &other_block) in other_blocks.iter().enumerate() {
                    let mut other_block_column = witness.new_column::<B128>(other_block);
                    let other_block_u128 = other_block_column.as_mut_slice::<u128>();

                    other_block_u128
                        .par_iter_mut()
                        .zip(&self.row_majors)
                        .for_each(|(dest, row_major)| {
                            *dest = u128::from_le_bytes(array::from_fn(|j| {
                                row_major.pre_hash_state[8 + i * 16 + j].to_underlier()
                            }));
                        });
                }
            }

            let mut all_blocks = vec![block0];
            all_blocks.extend(other_blocks);
            builder.receive(channel_ids.absorb_block, count, all_blocks);
        }
        // memory
        {
            let g = B32::MULTIPLICATIVE_GENERATOR;
            std::iter::successors(Some(g), |acc| Some(*acc * g))
                .take(32)
                .enumerate()
                .try_for_each(|(j, addr_coef)| {
                    let addr_pair = (hash_ptr, addr_coef * basis(32, 0));
                    let val_pair = (pre_hash_state[j], basis(32, 1));
                    // from mem pull (hash_ptr * g * g^j, pre_hash_state[j], read_tss[j])
                    let read_block = builder.add_linear_combination(
                        "flush 1, read_block",
                        n_vars,
                        [addr_pair, val_pair, (read_tss[j], basis(32, 2))],
                    )?;
                    builder.receive(channel_ids.mem, count, [read_block]);

                    // to mem push (hash_ptr * g * g^j, pre_hash_state[j], read_tss[j] * g)
                    let write_block = builder.add_linear_combination(
                        "flush 1, write_block",
                        n_vars,
                        [
                            addr_pair,
                            val_pair,
                            (read_tss[j], basis(32, 2) * B32::MULTIPLICATIVE_GENERATOR),
                        ],
                    )?;
                    builder.send(channel_ids.mem, count, [write_block]);

                    if let Some(witness) = builder.witness() {
                        (
                            witness
                                .new_column::<B128>(read_block)
                                .as_mut_slice::<u128>(),
                            witness
                                .new_column::<B128>(write_block)
                                .as_mut_slice::<u128>(),
                            witness.get::<B32>(hash_ptr)?.as_slice::<B32>(),
                            witness.get::<B8>(pre_hash_state[j])?.as_slice::<u8>(),
                            witness.get::<B32>(read_tss[j])?.as_slice::<B32>(),
                        )
                            .into_par_iter()
                            .for_each(
                                |(
                                    read_block,
                                    write_block,
                                    hash_ptr,
                                    pre_hash_state_j,
                                    read_tss_j,
                                )| {
                                    let addr = (*hash_ptr * addr_coef).to_underlier();
                                    *read_block = ((*read_tss_j).to_underlier() as u128) << 64
                                        | (*pre_hash_state_j as u128) << 32
                                        | (addr as u128);
                                    let incremented_ts =
                                        *read_tss_j * B32::MULTIPLICATIVE_GENERATOR;
                                    *write_block = (incremented_ts.to_underlier() as u128) << 64
                                        | (*pre_hash_state_j as u128) << 32
                                        | (addr as u128);
                                },
                            );
                    }

                    builder.assert_not_zero(read_tss[j]);

                    Ok::<_, anyhow::Error>(())
                })?;
        }
        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    fn absorb_block_base(
        &mut self,
        action: Action,
        pre_hash_state: [u8; HASH_B],
        preimage_ptr: u32,
        hash_ptr: u32,
    ) {
        assert_eq!(pre_hash_state.len(), HASH_B); // dev
        for (j, &state) in pre_hash_state.iter().enumerate().take(32) {
            assert_eq!(state, self.state.mem[hash_ptr + 1 + j as u32])
        }
        match action {
            Action::Append => self.absorb_block_base_table.append(
                &mut self.state,
                AbsorbBlockBaseData {
                    pre_hash_state,
                    preimage_ptr,
                    hash_ptr,
                },
            ),
            Action::Count => self.absorb_block_base_count += 1,
            Action::Ignore => (),
        }
    }
}

// RECURSIVE
pub(crate) struct AbsorbBlockRecursiveData {
    pre_hash_state: [u8; HASH_B],
    post_hash_state: [u8; HASH_B],
    preimage_block_vals: [u8; HASH_R],
    preimage_ptr: u32,
    hash_ptr: u32,
}

struct RecursiveRowMajors {
    pre_hash_state: [B8; HASH_B],
    post_hash_state: [B8; HASH_B],
    preimage_block_vals: [B8; HASH_R],
    read_tss: [B32; HASH_R],
    hash_ptr: B32,
    preimage_ptr: B32,
}

pub(crate) struct AbsorbBlockRecursiveTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    row_majors: Vec<RecursiveRowMajors>,
}
impl FunctionTable for AbsorbBlockRecursiveTable {
    type Data = AbsorbBlockRecursiveData;
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
        self.row_majors.push(RecursiveRowMajors {
            pre_hash_state: array::from_fn(|i| B8::from_underlier(data.pre_hash_state[i])),
            post_hash_state: array::from_fn(|i| B8::from_underlier(data.post_hash_state[i])),
            preimage_block_vals: array::from_fn(|i| {
                B8::from_underlier(data.preimage_block_vals[i])
            }),
            read_tss: array::from_fn(|i| {
                mpt_state
                    .mem
                    .process_timestamp(data.preimage_ptr + i as u32)
            }),
            hash_ptr: mpt_state.mem.to_mult(data.hash_ptr),
            preimage_ptr: mpt_state.mem.to_mult(data.preimage_ptr),
        });

        self.index += 1;
    }
    #[instrument(
        name = "absorb_block_recursive",
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
        builder.push_namespace("absorb_block_recursive");
        assert_eq!(self.index, self.count);
        if builder.witness().is_some() {
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let pre_hash_state =
            builder.add_committed_multiple::<HASH_B>("pre_hash_state", n_vars, B8::TOWER_LEVEL);
        let post_hash_state =
            builder.add_committed_multiple::<HASH_B>("post_hash_state", n_vars, B8::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let mut pre_hash_state_columns = pre_hash_state.map(|id| witness.new_column::<B8>(id));
            let pre_hash_state_slices = pre_hash_state_columns
                .each_mut()
                .map(move |col| col.as_mut_slice::<B8>());

            let mut post_hash_state_columns =
                post_hash_state.map(|id| witness.new_column::<B8>(id));
            let post_hash_state_slices = post_hash_state_columns
                .each_mut()
                .map(move |col| col.as_mut_slice::<B8>());

            // parallelize this
            for (i, row_majors) in self.row_majors.iter().enumerate() {
                for (j, value) in row_majors.pre_hash_state.iter().enumerate() {
                    pre_hash_state_slices[j][i] = *value;
                }
                for (j, value) in row_majors.post_hash_state.iter().enumerate() {
                    post_hash_state_slices[j][i] = *value;
                }
            }
        }

        let preimage_block_vals = builder.add_committed_multiple::<HASH_R>(
            "preimage_block_vals",
            n_vars,
            B8::TOWER_LEVEL,
        );
        let read_tss =
            builder.add_committed_multiple::<HASH_R>("read_tss", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let mut preimage_block_vals_columns =
                preimage_block_vals.map(|id| witness.new_column::<B8>(id));
            let preimage_block_vals_slices = preimage_block_vals_columns
                .each_mut()
                .map(move |col| col.as_mut_slice::<B8>());

            let mut read_tss_columns =
                read_tss.map(|id| witness.new_column_with_default::<B32>(id, B32::one()));
            let read_tss_slices = read_tss_columns
                .each_mut()
                .map(move |col| col.as_mut_slice::<B32>());

            // parallelize this
            for (i, row_majors) in self.row_majors.iter().enumerate() {
                for (j, value) in row_majors.preimage_block_vals.iter().enumerate() {
                    preimage_block_vals_slices[j][i] = *value;
                }
                for (j, value) in row_majors.read_tss.iter().enumerate() {
                    read_tss_slices[j][i] = *value;
                }
            }
        }

        let preimage_ptr = builder.add_committed("preimage_ptr", n_vars, B32::TOWER_LEVEL);
        let hash_ptr = builder.add_committed("hash_ptr", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let par_data_iter = &self.row_majors;
            populate_committed_polys!(
                par_data_iter,
                witness,
                [(preimage_ptr, B32), (hash_ptr, B32),]
            );
        }

        // from absorb_block pull (preimage_ptr, hash_ptr, pre_hash_state)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (preimage_ptr, basis(32, 0)),
                    (hash_ptr, basis(32, 1)),
                    (pre_hash_state[0], basis(8, 8)),
                    (pre_hash_state[1], basis(8, 8 + 1)),
                    (pre_hash_state[2], basis(8, 8 + 2)),
                    (pre_hash_state[3], basis(8, 8 + 3)),
                    (pre_hash_state[4], basis(8, 8 + 4)),
                    (pre_hash_state[5], basis(8, 8 + 5)),
                    (pre_hash_state[6], basis(8, 8 + 6)),
                    (pre_hash_state[7], basis(8, 8 + 7)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let mut block0_column = witness.new_column::<B128>(block0);
                let block0_u128 = block0_column.as_mut_slice::<u128>();

                block0_u128
                    .par_iter_mut()
                    .zip(&self.row_majors)
                    .for_each(|(dest, row_major)| {
                        let bytes = u64::from_le_bytes(array::from_fn(|j| {
                            row_major.pre_hash_state[j].to_underlier()
                        }));
                        *dest = (bytes as u128) << 64
                            | (row_major.hash_ptr.to_underlier() as u128) << 32
                            | (row_major.preimage_ptr.to_underlier() as u128);
                    });
            }

            let other_blocks: Vec<OracleId> = (0..12)
                .map(|i| {
                    let id = builder.add_linear_combination(
                        "flush 0, other_blocks",
                        n_vars,
                        (0..16)
                            .map(|j| (pre_hash_state[8 + i * 16 + j], basis(8, j)))
                            .collect::<Vec<_>>(),
                    )?;
                    Ok(id)
                })
                .collect::<Result<_, anyhow::Error>>()?;
            if let Some(witness) = builder.witness() {
                for (i, &other_block) in other_blocks.iter().enumerate() {
                    let mut other_block_column = witness.new_column::<B128>(other_block);
                    let other_block_u128 = other_block_column.as_mut_slice::<u128>();

                    other_block_u128
                        .par_iter_mut()
                        .zip(&self.row_majors)
                        .for_each(|(dest, row_major)| {
                            *dest = u128::from_le_bytes(array::from_fn(|j| {
                                row_major.pre_hash_state[8 + i * 16 + j].to_underlier()
                            }));
                        });
                }
            }

            let mut all_blocks = vec![block0];
            all_blocks.extend(other_blocks);
            builder.receive(channel_ids.absorb_block, count, all_blocks);
        }
        // memory
        {
            let g = B32::MULTIPLICATIVE_GENERATOR;
            std::iter::successors(Some(B32::one()), |acc| Some(*acc * g))
                .take(HASH_R)
                .enumerate()
                .try_for_each(|(j, addr_coef)| {
                    let addr_pair = (preimage_ptr, addr_coef * basis(32, 0));
                    let val_pair = (preimage_block_vals[j], basis(32, 1));

                    // from mem pull (preimage_ptr * g^j, preimage_block_vals[j], read_tss[j])
                    let read_block = builder.add_linear_combination(
                        "flush 1, read block",
                        n_vars,
                        [addr_pair, val_pair, (read_tss[j], basis(32, 2))],
                    )?;
                    builder.receive(channel_ids.mem, count, [read_block]);

                    // to mem pull (preimage_ptr * g^j, preimage_block_vals[j], read_tss[j] * g)
                    let write_block = builder.add_linear_combination(
                        "flush 1, write block",
                        n_vars,
                        [
                            addr_pair,
                            val_pair,
                            (read_tss[j], basis(32, 2) * B32::MULTIPLICATIVE_GENERATOR),
                        ],
                    )?;
                    builder.send(channel_ids.mem, count, [write_block]);

                    if let Some(witness) = builder.witness() {
                        (
                            witness
                                .new_column::<B128>(read_block)
                                .as_mut_slice::<u128>(),
                            witness
                                .new_column::<B128>(write_block)
                                .as_mut_slice::<u128>(),
                            witness.get::<B32>(preimage_ptr)?.as_slice::<B32>(),
                            witness.get::<B8>(preimage_block_vals[j])?.as_slice::<u8>(),
                            witness.get::<B32>(read_tss[j])?.as_slice::<B32>(),
                        )
                            .into_par_iter()
                            .for_each(
                                |(
                                    read_block,
                                    write_block,
                                    preimage_ptr,
                                    preimage_block_vals_j,
                                    read_tss_j,
                                )| {
                                    let addr = (*preimage_ptr * addr_coef).to_underlier();
                                    *read_block = ((*read_tss_j).to_underlier() as u128) << 64
                                        | (*preimage_block_vals_j as u128) << 32
                                        | (addr as u128);
                                    let incremented_ts =
                                        *read_tss_j * B32::MULTIPLICATIVE_GENERATOR;
                                    *write_block = (incremented_ts.to_underlier() as u128) << 64
                                        | (*preimage_block_vals_j as u128) << 32
                                        | (addr as u128);
                                },
                            );
                    }

                    Ok::<_, anyhow::Error>(())
                })?;
        }
        // to keccak_f push (
        //      pre_hash_state[i] XOR block_vals[i] for i in 0..HASH_R
        //      CONCAT pre_hash_state[i] for i in HASH_R..HASH_B
        // , post_hash_state)
        {
            // low blocks handled last
            let middle_block = builder.add_linear_combination(
                "middle_block",
                n_vars,
                [
                    (pre_hash_state[192], basis(8, 0)),
                    (pre_hash_state[192 + 1], basis(8, 1)),
                    (pre_hash_state[192 + 2], basis(8, 2)),
                    (pre_hash_state[192 + 3], basis(8, 3)),
                    (pre_hash_state[192 + 4], basis(8, 4)),
                    (pre_hash_state[192 + 5], basis(8, 5)),
                    (pre_hash_state[192 + 6], basis(8, 6)),
                    (pre_hash_state[192 + 7], basis(8, 7)),
                    (post_hash_state[0], basis(8, 8)),
                    (post_hash_state[1], basis(8, 8 + 1)),
                    (post_hash_state[2], basis(8, 8 + 2)),
                    (post_hash_state[3], basis(8, 8 + 3)),
                    (post_hash_state[4], basis(8, 8 + 4)),
                    (post_hash_state[5], basis(8, 8 + 5)),
                    (post_hash_state[6], basis(8, 8 + 6)),
                    (post_hash_state[7], basis(8, 8 + 7)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let mut middle_block_column = witness.new_column::<B128>(middle_block);
                let middle_block_u128 = middle_block_column.as_mut_slice::<u128>();

                middle_block_u128
                    .par_iter_mut()
                    .zip(&self.row_majors)
                    .for_each(|(dest, row_major)| {
                        let bytes_low = u64::from_le_bytes(array::from_fn(|j| {
                            row_major.pre_hash_state[192 + j].to_underlier()
                        }));

                        let bytes_high = u64::from_le_bytes(array::from_fn(|j| {
                            row_major.post_hash_state[j].to_underlier()
                        }));

                        *dest = (bytes_low as u128) | (bytes_high as u128) << 64;
                    });
            }

            let high_blocks: Vec<OracleId> = (0..12)
                .map(|i| {
                    Ok(builder.add_linear_combination(
                        "high_blocks",
                        n_vars,
                        array::from_fn::<_, 16, _>(|j| {
                            (post_hash_state[8 + i * 16 + j], basis(8, j))
                        }),
                    )?)
                })
                .collect::<Result<_, anyhow::Error>>()?;
            if let Some(witness) = builder.witness() {
                for (i, &high_block) in high_blocks.iter().enumerate() {
                    let mut high_block_column = witness.new_column::<B128>(high_block);
                    let high_block_u128 = high_block_column.as_mut_slice::<u128>();

                    high_block_u128
                        .par_iter_mut()
                        .zip(&self.row_majors)
                        .for_each(|(dest, row_major)| {
                            *dest = u128::from_le_bytes(array::from_fn(|j| {
                                row_major.post_hash_state[8 + i * 16 + j].to_underlier()
                            }));
                        });
                }
            }

            // low blocks
            let mut low_blocks: Vec<Vec<(OracleId, B128)>> = (0..12)
                .map(|i| {
                    (0..16)
                        .map(|j| (pre_hash_state[i * 16 + j], basis(8, j)))
                        .collect()
                })
                .collect();

            // extend low blocks further with preimage (preimage will get added to part of pre_hash_state)
            let preimage_block_vals_low_blocks: Vec<Vec<(OracleId, B128)>> = (0..8)
                .map(|i| {
                    (0..16)
                        .map(|j| (preimage_block_vals[i * 16 + j], basis(8, j)))
                        .collect()
                })
                .collect();
            let preimage_block_vals_high_block: Vec<(OracleId, B128)> = (0..8)
                .map(|j| (preimage_block_vals[128 + j], basis(8, j)))
                .collect();
            for (j, block) in preimage_block_vals_low_blocks.into_iter().enumerate() {
                low_blocks[j].extend(block);
            }
            low_blocks[8].extend(preimage_block_vals_high_block);

            /*
            12 x 16 pre_hash_state
            8 x 16 preimage_block_vals_low_blocks
            1 x 8 preimage_block_vals_high_block [128 + j] 136 total
            */

            let low_blocks: Vec<OracleId> = low_blocks
                .into_iter()
                .map(|low_block| {
                    Ok(builder.add_linear_combination("low_blocks", n_vars, low_block)?)
                })
                .collect::<Result<_, anyhow::Error>>()?;

            if let Some(witness) = builder.witness() {
                for (i, &low_block) in low_blocks.iter().enumerate() {
                    let mut low_block_column = witness.new_column::<B128>(low_block);
                    let low_block_u128 = low_block_column.as_mut_slice::<u128>();

                    low_block_u128
                        .par_iter_mut()
                        .zip(&self.row_majors)
                        .for_each(|(dest, row_major)| {
                            let pre_hash_state_bytes = u128::from_le_bytes(array::from_fn(|j| {
                                row_major.pre_hash_state[i * 16 + j].to_underlier()
                            }));

                            let preimage_block_vals_bytes =
                                u128::from_le_bytes(array::from_fn(|j| {
                                    row_major
                                        .preimage_block_vals
                                        .get(i * 16 + j)
                                        .map_or(0, |b8| b8.to_underlier())
                                }));

                            *dest = pre_hash_state_bytes ^ preimage_block_vals_bytes;
                        });
                }
            }

            let mut all_blocks = vec![];
            all_blocks.extend(low_blocks);
            all_blocks.push(middle_block);
            all_blocks.extend(high_blocks);
            assert_eq!(all_blocks.len(), 25);

            builder.send(channel_ids.keccak_f, count, all_blocks);
        }
        // to absorb_block push (preimage_ptr * g^HASH_R, hash_ptr, post_hash_state)
        {
            let g_pow_hash_r = B32::MULTIPLICATIVE_GENERATOR.pow([HASH_R as u64]);

            let block0 = builder.add_linear_combination(
                "flush 3, block 0",
                n_vars,
                [
                    (preimage_ptr, basis(32, 0) * g_pow_hash_r),
                    (hash_ptr, basis(32, 1)),
                    (post_hash_state[0], basis(8, 8)),
                    (post_hash_state[1], basis(8, 8 + 1)),
                    (post_hash_state[2], basis(8, 8 + 2)),
                    (post_hash_state[3], basis(8, 8 + 3)),
                    (post_hash_state[4], basis(8, 8 + 4)),
                    (post_hash_state[5], basis(8, 8 + 5)),
                    (post_hash_state[6], basis(8, 8 + 6)),
                    (post_hash_state[7], basis(8, 8 + 7)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                let mut block0_column = witness.new_column::<B128>(block0);
                let block0_u128 = block0_column.as_mut_slice::<u128>();

                block0_u128
                    .par_iter_mut()
                    .zip(&self.row_majors)
                    .for_each(|(dest, row_major)| {
                        let bytes = u64::from_le_bytes(array::from_fn(|j| {
                            row_major.post_hash_state[j].to_underlier()
                        }));

                        *dest = (bytes as u128) << 64
                            | (row_major.hash_ptr.to_underlier() as u128) << 32
                            | ((row_major.preimage_ptr * g_pow_hash_r).to_underlier() as u128);
                    });
            }

            let other_blocks: Vec<OracleId> = (0..12)
                .map(|i| {
                    Ok(builder.add_linear_combination(
                        "flush 3, other_blocks",
                        n_vars,
                        (0..16)
                            .map(|j| (post_hash_state[8 + i * 16 + j], basis(8, j)))
                            .collect::<Vec<_>>(),
                    )?)
                })
                .collect::<Result<_, anyhow::Error>>()?;
            if let Some(witness) = builder.witness() {
                for (i, &other_block) in other_blocks.iter().enumerate() {
                    let mut other_block_column = witness.new_column::<B128>(other_block);
                    let other_block_u128 = other_block_column.as_mut_slice::<u128>();

                    other_block_u128
                        .par_iter_mut()
                        .zip(&self.row_majors)
                        .for_each(|(dest, row_major)| {
                            *dest = u128::from_le_bytes(array::from_fn(|j| {
                                row_major.post_hash_state[8 + i * 16 + j].to_underlier()
                            }));
                        });
                }
            }

            let mut all_blocks = vec![block0];
            all_blocks.extend(other_blocks);
            builder.send(channel_ids.absorb_block, count, all_blocks);
        }
        builder.pop_namespace();
        Ok(())
    }
}

impl MPT {
    fn absorb_block_recursive(
        &mut self,
        action: Action,
        pre_hash_state: [u8; HASH_B],
        preimage_ptr: u32,
        hash_ptr: u32,
        blocks_left: u8,
    ) {
        assert!(blocks_left > 0); // dev
        let preimage_block_vals =
            self.state.mem[preimage_ptr..preimage_ptr + HASH_R as u32].to_vec();
        let mut perm_input = pre_hash_state;
        for j in 0..HASH_R {
            perm_input[j] ^= preimage_block_vals[j]
        }
        let post_hash_state = self.keccak_f(action, perm_input);
        assert_eq!(post_hash_state, crate::utils::keccak_f(perm_input));

        self.absorb_block(
            action,
            post_hash_state,
            preimage_ptr + HASH_R as u32,
            hash_ptr,
            blocks_left - 1,
        );
        match action {
            Action::Append => self.absorb_block_recursive_table.append(
                &mut self.state,
                AbsorbBlockRecursiveData {
                    pre_hash_state,
                    post_hash_state,
                    preimage_block_vals: preimage_block_vals.try_into().unwrap(),
                    preimage_ptr,
                    hash_ptr,
                },
            ),
            Action::Count => self.absorb_block_recursive_count += 1,
            Action::Ignore => (),
        }
    }
}
