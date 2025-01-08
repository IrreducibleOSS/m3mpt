// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct SkipListHeaderOffsetLookupTable {
    final_ts: Vec<B32>,
}

impl SkipListHeaderOffsetLookupTable {
    pub(crate) fn new() -> Self {
        Self {
            final_ts: Vec::with_capacity(256),
        }
    }
    pub(crate) fn populate(&mut self, mpt_state: &mut MPTState) {
        (192..=u8::MAX).for_each(|prefix_val| {
            self.final_ts.push(
                mpt_state
                    .skip_list_header_offset_lookup
                    .process_timestamp(prefix_val),
            );
        });
    }
    #[instrument(
        name = "skip_list_header_offset_lookup",
        fields(n_vars = 8)
        skip_all,
        level = "debug"
    )]
    pub(crate) fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
    ) -> Result<(), anyhow::Error> {
        let n_vars = 6;

        let final_ts = builder.add_committed("final_ts", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let mut col = witness.new_column::<B32>(final_ts);
            col.as_mut_slice::<B32>().copy_from_slice(&self.final_ts);
        }

        let prefix_val_values = {
            let mut vals: Vec<u8> = (192..=u8::MAX).collect();
            vals.resize(64, 0);
            vals
        };
        let offset_values: Vec<B32> = {
            let mult_map: Vec<_> = std::iter::successors(Some(B32::ONE), |power| {
                Some(*power * B32::MULTIPLICATIVE_GENERATOR)
            })
            .take(256)
            .collect();
            prefix_val_values
                .iter()
                .map(|prefix_val| {
                    mult_map[MPT::skip_list_header_offset_lookup(*prefix_val) as usize]
                })
                .collect()
        };
        let prefix_val = make_transparent::<B8>(
            builder,
            "prefix_val",
            bytemuck::must_cast_slice(&prefix_val_values),
        )?;
        let offset = make_transparent::<B32>(builder, "offset", &offset_values)?;

        let count = 64;

        // to offset_lookup push (prefix_val, offset, 1)
        {
            let block0 = builder.add_linear_combination_with_offset(
                "flush 0, block 0",
                n_vars,
                basis(32, 2),
                [(prefix_val, basis(32, 0)), (offset, basis(32, 1))],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B8>(prefix_val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, prefix_val, offset)| {
                        *block = 1 << 64 | (*offset as u128) << 32 | (*prefix_val as u128);
                    });
            }

            builder.send(channel_ids.skip_list_header_offset_lookup, count, [block0]);
        }
        // from offset_lookup pull (prefix_val, offset, ts)
        {
            let block0 = builder.add_linear_combination(
                "flush 0, block 0",
                n_vars,
                [
                    (prefix_val, basis(32, 0)),
                    (offset, basis(32, 1)),
                    (final_ts, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B8>(prefix_val)?.as_slice::<u8>(),
                    witness.get::<B32>(offset)?.as_slice::<u32>(),
                    witness.get::<B32>(final_ts)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, prefix_val, offset, ts)| {
                        *block =
                            (*ts as u128) << 64 | (*offset as u128) << 32 | (*prefix_val as u128);
                    });
            }

            builder.receive(channel_ids.skip_list_header_offset_lookup, count, [block0]);
        }

        Ok(())
    }
}
impl MPT {
    pub fn skip_list_header_offset_lookup(prefix_val: u8) -> u8 {
        assert!(prefix_val >= 192);
        1 + match prefix_val & 0xf8 == 0xf8 {
            true => prefix_val - 247,
            false => 0,
        }
    }
}

pub struct SkipListHeaderOffsetLookup {
    timestamps: [B32; 64],
}
impl SkipListHeaderOffsetLookup {
    pub fn new() -> Self {
        Self {
            timestamps: [B32::ONE; 64],
        }
    }
    pub fn process_timestamp(&mut self, index: u8) -> B32 {
        let index = index - 192;
        let ts = self.timestamps[index as usize];
        self.timestamps[index as usize] *= B32::MULTIPLICATIVE_GENERATOR;
        ts
    }
}
