// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct GetChildOffsetLookupTable {
    final_ts: Vec<B32>,
}

impl GetChildOffsetLookupTable {
    pub(crate) fn new() -> Self {
        Self {
            final_ts: Vec::with_capacity(256),
        }
    }
    pub(crate) fn populate(&mut self, mpt_state: &mut MPTState) {
        (0..=u8::MAX).for_each(|prefix_val| {
            self.final_ts.push(
                mpt_state
                    .get_child_offset_lookup
                    .process_timestamp(prefix_val),
            );
        });
    }
    #[instrument(
        name = "ext_leaf_trans",
        fields(n_vars = 8)
        skip_all,
        level = "debug"
    )]
    pub(crate) fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
    ) -> Result<(), anyhow::Error> {
        let n_vars = 8;

        let final_ts = builder.add_committed("final_ts", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            let mut c = witness.new_column::<B32>(final_ts);
            let y = c.as_mut_slice::<B32>();
            y.copy_from_slice(&self.final_ts);
        }

        let prefix_val_values: Vec<u8> = (0..=u8::MAX).collect();
        let offset_values: Vec<B32> = {
            let mult_map: Vec<B32> = (0..=u8::MAX)
                .scan(B32::ONE, |acc, _| {
                    let out = *acc;
                    *acc *= B32::MULTIPLICATIVE_GENERATOR;
                    Some(out)
                })
                .collect();
            (0..=u8::MAX)
                .map(|val| mult_map[GetChildOffsetLookup::query(val) as usize])
                .collect()
        };
        let val = make_transparent::<B8>(
            builder,
            "val",
            bytemuck::must_cast_slice(&prefix_val_values),
        )?;
        let offset = make_transparent::<B32>(builder, "offset", &offset_values)?;

        let block0 = builder.add_linear_combination_with_offset(
            "flush 0, block 0",
            n_vars,
            basis(32, 2),
            [(val, basis(32, 0)), (offset, basis(32, 1))],
        )?;
        if let Some(witness) = builder.witness() {
            (
                witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                witness.get::<B8>(val)?.as_slice::<u8>(),
                witness.get::<B32>(offset)?.as_slice::<u32>(),
            )
                .into_par_iter()
                .for_each(|(block, prefix_val, offset)| {
                    *block = 1 << 64 | (*offset as u128) << 32 | (*prefix_val as u128);
                });
        }

        builder.send(channel_ids.get_child_offset_lookup, 256, [block0]);

        let block0 = builder.add_linear_combination(
            "flush 0, block 0",
            n_vars,
            [
                (val, basis(32, 0)),
                (offset, basis(32, 1)),
                (final_ts, basis(32, 2)),
            ],
        )?;
        if let Some(witness) = builder.witness() {
            (
                witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                witness.get::<B8>(val)?.as_slice::<u8>(),
                witness.get::<B32>(offset)?.as_slice::<u32>(),
                witness.get::<B32>(final_ts)?.as_slice::<u32>(),
            )
                .into_par_iter()
                .for_each(|(block, val, offset, ts)| {
                    *block = (*ts as u128) << 64 | (*offset as u128) << 32 | (*val as u128);
                });
        }

        builder.receive(channel_ids.get_child_offset_lookup, 256, [block0]);

        Ok(())
    }
}

pub(crate) struct GetChildOffsetLookup {
    timestamps: [B32; 256],
}
impl GetChildOffsetLookup {
    pub fn new() -> Self {
        Self {
            timestamps: [B32::ONE; 256],
        }
    }
    pub fn process_timestamp(&mut self, index: u8) -> B32 {
        let ts = self.timestamps[index as usize];
        self.timestamps[index as usize] *= B32::MULTIPLICATIVE_GENERATOR;
        ts
    }
    pub fn query(val: u8) -> u8 {
        match val & 0x20 == 0x20 {
            true => 1 + 32,
            false => 1,
        }
    }
}
