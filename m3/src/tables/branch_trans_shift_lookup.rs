// Copyright 2024 Irreducible Inc.

use super::*;
pub(crate) struct BranchTransShiftLookupTable {
    final_ts: Vec<B32>,
}

impl BranchTransShiftLookupTable {
    pub(crate) fn new() -> Self {
        Self {
            final_ts: Vec::with_capacity(256),
        }
    }
    pub(crate) fn populate(&mut self, mpt_state: &mut MPTState) {
        for key_ptr_parity in [true, false] {
            (0..=u8::MAX).for_each(|key_val| {
                self.final_ts.push(
                    mpt_state
                        .branch_trans_shift_lookup
                        .process_timestamp(key_ptr_parity, key_val),
                );
            });
        }
    }
    #[instrument(
        name = "branch_trans_shift_lookup",
        fields(n_vars = 9)
        skip_all,
        level = "debug"
    )]
    pub(crate) fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
    ) -> Result<(), anyhow::Error> {
        let n_vars = 9;
        let final_ts = builder.add_committed("final_ts", n_vars, B32::TOWER_LEVEL);

        if let Some(witness) = builder.witness() {
            let mut col = witness.new_column::<B32>(final_ts);
            col.as_mut_slice::<B32>().copy_from_slice(&self.final_ts);
        }

        let lookup_values: Vec<B32> = {
            let mut values = Vec::with_capacity(1 << n_vars);
            for key_ptr_parity in [true, false] {
                values.extend(
                    (0..=u8::MAX)
                        .map(|key_val| {
                            (match key_ptr_parity {
                                true => B32::ONE,
                                false => B32::ZERO,
                            }) * <B32 as ExtensionField<BinaryField1b>>::basis(0).unwrap()
                                + B8::from_underlier(key_val)
                                    * <B32 as ExtensionField<BinaryField1b>>::basis(8).unwrap()
                                + BranchTransShiftLookup::query(key_ptr_parity, key_val)
                                    * <B32 as ExtensionField<BinaryField1b>>::basis(16).unwrap()
                        })
                        .collect::<Vec<B32>>(),
                )
            }
            values
        };
        let lookup_val = make_transparent::<B32>(builder, "lookup_val", &lookup_values)?;

        let read_block = builder.add_linear_combination_with_offset(
            "read_block",
            n_vars,
            basis(32, 1),
            [(lookup_val, basis(32, 0))],
        )?;
        if let Some(witness) = builder.witness() {
            (
                witness
                    .new_column::<B128>(read_block)
                    .as_mut_slice::<u128>(),
                witness.get::<B32>(lookup_val)?.as_slice::<u32>(),
            )
                .into_par_iter()
                .for_each(|(block, lookup_val)| {
                    *block = 1 << 32 | (*lookup_val as u128);
                });
        }

        builder.send(
            channel_ids.branch_trans_shift_lookup,
            1 << n_vars,
            [read_block],
        );

        let write_block = builder.add_linear_combination(
            "write_block",
            n_vars,
            [(lookup_val, basis(32, 0)), (final_ts, basis(32, 1))],
        )?;
        if let Some(witness) = builder.witness() {
            (
                witness
                    .new_column::<B128>(write_block)
                    .as_mut_slice::<u128>(),
                witness.get::<B32>(lookup_val)?.as_slice::<u32>(),
                witness.get::<B32>(final_ts)?.as_slice::<u32>(),
            )
                .into_par_iter()
                .for_each(|(block, lookup_val, final_ts)| {
                    *block = (*final_ts as u128) << 32 | (*lookup_val as u128);
                });
        }

        builder.receive(
            channel_ids.branch_trans_shift_lookup,
            1 << n_vars,
            [write_block],
        );

        Ok(())
    }
}

pub(crate) struct BranchTransShiftLookup {
    timestamps: [B32; 512],
}
impl BranchTransShiftLookup {
    pub(crate) fn new() -> Self {
        Self {
            timestamps: [B32::ONE; 512],
        }
    }
    pub(crate) fn process_timestamp(&mut self, key_ptr_parity: bool, key_val: u8) -> B32 {
        let index = key_val as usize
            + match key_ptr_parity {
                true => 1 << 8,
                false => 0,
            };
        let ts = self.timestamps[index];
        self.timestamps[index] *= B32::MULTIPLICATIVE_GENERATOR;
        ts
    }
    pub(crate) fn query(key_ptr_parity: bool, key_val: u8) -> B8 {
        let shift = match key_ptr_parity {
            true => 0,
            false => 4,
        };
        let index_nib = (key_val >> shift) & 0x0f;
        U8_TO_MULT_MAP[index_nib as usize]
    }
}
