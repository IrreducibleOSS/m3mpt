// Copyright 2024 Irreducible Inc.

use binius_circuits::keccakf::{keccakf, KeccakfOracles, KeccakfState};

use super::*;

pub struct KeccakFData {
    perm_input: [u64; HASH_B / 8],
}

pub struct KeccakFTable {
    n_vars: usize,
    count: usize,
    index: usize,
    _smallest_tower_level: usize,
    perm_input: Vec<KeccakfState>,
}
impl FunctionTable for KeccakFTable {
    type Data = KeccakFData;
    fn new() -> Self {
        Self {
            n_vars: 0,
            count: 0,
            index: 0,
            _smallest_tower_level: 6,
            perm_input: vec![],
        }
    }
    fn allocate(&mut self, count: usize) -> usize {
        self.perm_input = Vec::with_capacity(count);

        self.count = count;
        self.n_vars = std::cmp::max(
            self.count.next_power_of_two().trailing_zeros() as usize,
            U::LOG_BITS + 2, // - self.smallest_tower_level,
        );
        self.n_vars
    }
    fn append(&mut self, _mpt_state: &mut MPTState, data: Self::Data) {
        self.perm_input.push(KeccakfState(data.perm_input));
        self.index += 1;
    }
    #[instrument(
        name = "keccak_f",
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
        builder.push_namespace("keccak_f");
        if builder.witness().is_some() {
            assert_eq!(self.index, self.count);
            assert_eq!(self.n_vars, n_vars);
            assert_eq!(self.count, count);
        }

        let keccakf_states = builder.witness().map(|_| &self.perm_input);

        let KeccakfOracles {
            input: packed_input,
            output: packed_output,
        } = keccakf(builder, keccakf_states, n_vars)?;

        let lower_halves = (0..25)
            .map(|i| {
                if i <= 12 {
                    packed_input[2 * i]
                } else {
                    packed_output[2 * (i - 13) + 1]
                }
            })
            .collect::<Vec<_>>();

        let upper_halves = (0..25)
            .map(|i| {
                if i < 12 {
                    packed_input[2 * i + 1]
                } else {
                    packed_output[2 * (i - 12)]
                }
            })
            .collect::<Vec<_>>();

        let flushed_blocks = izip!(&lower_halves, &upper_halves)
            .enumerate()
            .map(|(i, (&lower_half, &upper_half))| {
                Ok(builder.add_linear_combination(
                    format!("keccakf_flushed_block_{}", i),
                    n_vars,
                    [(lower_half, basis(64, 0)), (upper_half, basis(64, 1))],
                )?)
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        if let Some(witness) = builder.witness() {
            for (&flushed_block, lower_half, upper_half) in
                izip!(&flushed_blocks, lower_halves, upper_halves)
            {
                let mut flushed_block_column = witness.new_column::<B128>(flushed_block);
                let flushed_block_u128 = flushed_block_column.as_mut_slice::<u128>();

                let lower_half = witness.get::<B64>(lower_half)?;
                let upper_half = witness.get::<B64>(upper_half)?;

                flushed_block_u128
                    .par_iter_mut()
                    .zip(lower_half.as_slice::<u64>())
                    .zip(upper_half.as_slice::<u64>())
                    .for_each(|((dest, &lower_half), &upper_half)| {
                        *dest = (lower_half as u128) | (upper_half as u128) << 64;
                    });
            }
        }

        builder.receive(channel_ids.keccak_f, count, flushed_blocks);

        builder.pop_namespace();
        Ok(())
    }
}

fn to_u64_array(bytes: &[u8; 200]) -> [u64; 25] {
    let mut u64_array = [0u64; 25];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        u64_array[i] = u64::from_ne_bytes(chunk.try_into().unwrap());
    }
    u64_array
}
impl MPT {
    pub(crate) fn keccak_f(&mut self, action: Action, perm_input: [u8; HASH_B]) -> [u8; HASH_B] {
        let old_perm_output = crate::utils::keccak_f(perm_input);
        let perm_input = to_u64_array(&perm_input);
        match action {
            Action::Append => self
                .keccak_f_table
                .append(&mut self.state, KeccakFData { perm_input }),
            Action::Count => self.keccak_f_count += 1,
            Action::Ignore => (),
        }
        old_perm_output
    }
}
