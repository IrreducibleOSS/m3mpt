// Copyright 2024 Irreducible Inc.

use super::*;

pub(crate) struct PopulateMemTable;

impl PopulateMemTable {
    pub(crate) fn new() -> Self {
        Self {}
    }
    #[instrument(
        name = "populate_mem",
        fields(n_vars = n_vars)
        skip_all,
        level = "debug"
    )]
    pub(crate) fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
        mpt_state: &mut MPTState,
        n_vars: usize,
    ) -> Result<(), anyhow::Error> {
        builder.push_namespace("populate_mem");

        let powers = binius_core::transparent::powers::Powers::new(
            n_vars,
            B128::ONE * B32::MULTIPLICATIVE_GENERATOR,
        );
        let addr = builder.add_transparent("addr", powers)?;
        if let Some(witness) = builder.witness() {
            witness
                .new_column::<B32>(addr)
                .as_mut_slice::<B32>()
                .into_par_iter()
                .enumerate()
                .for_each(|(i, entry)| *entry = mpt_state.mem.to_mult(i as u32));
        }

        let val = builder.add_committed("val", n_vars, B8::TOWER_LEVEL);
        let ts = builder.add_committed("ts", n_vars, B32::TOWER_LEVEL);
        if let Some(witness) = builder.witness() {
            izip!(
                witness.new_column::<B8>(val).as_mut_slice::<B8>(),
                witness.new_column::<B32>(ts).as_mut_slice::<B32>(),
            )
            .enumerate()
            .for_each(|(addr, (val, ts))| {
                *val = B8::from_underlier(mpt_state.mem[addr as u32]);
                *ts = mpt_state.mem.process_timestamp(addr as u32);
            });
        }

        // to mem push (addr, val, 1)
        {
            let block0 = builder.add_linear_combination_with_offset(
                "flush 0, block 0",
                n_vars,
                basis(32, 2),
                [(addr, basis(32, 0)), (val, basis(32, 1))],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(addr)?.as_slice::<u32>(),
                    witness.get::<B8>(val)?.as_slice::<u8>(),
                )
                    .into_par_iter()
                    .for_each(|(block, addr, val)| {
                        *block = (1 << 64) | (*val as u128) << 32 | (*addr as u128);
                    });
            }
            builder.flush(FlushDirection::Push, channel_ids.mem, 1 << n_vars, [block0]);
        }
        // from mem pull (addr, val, ts)
        {
            let block0 = builder.add_linear_combination(
                "flush 1, block 0",
                n_vars,
                [
                    (addr, basis(32, 0)),
                    (val, basis(32, 1)),
                    (ts, basis(32, 2)),
                ],
            )?;
            if let Some(witness) = builder.witness() {
                (
                    witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
                    witness.get::<B32>(addr)?.as_slice::<u32>(),
                    witness.get::<B8>(val)?.as_slice::<u8>(),
                    witness.get::<B32>(ts)?.as_slice::<u32>(),
                )
                    .into_par_iter()
                    .for_each(|(block, addr, val, ts)| {
                        *block = (*ts as u128) << 64 | (*val as u128) << 32 | (*addr as u128);
                    });
            }
            builder.flush(FlushDirection::Pull, channel_ids.mem, 1 << n_vars, [block0]);
        }

        builder.pop_namespace();
        Ok(())
    }
}
