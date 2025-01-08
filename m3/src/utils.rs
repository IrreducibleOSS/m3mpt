// Copyright 2024 Irreducible Inc.

use core::iter::Iterator;

use super::*;

// memory
pub struct Memory {
    mem: Vec<u8>,
    timestamps: Vec<B32>,
    powers: Vec<B32>,
}
impl Memory {
    pub fn new() -> Self {
        Self {
            mem: Vec::new(),
            timestamps: Vec::new(),
            powers: Vec::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.mem.len()
    }
    pub fn cursor(&self) -> u32 {
        self.len() as u32
    }
    pub fn append(&mut self, data: &[u8]) {
        // extend powers
        let mut next_power = match self.len() {
            0 => B32::ONE,
            _ => self.powers[self.len() - 1] * B32::MULTIPLICATIVE_GENERATOR,
        };
        for _ in 0..data.len() {
            self.powers.push(next_power);
            next_power *= B32::MULTIPLICATIVE_GENERATOR;
        }
        // extend mem
        self.mem.extend_from_slice(data);
        // extend counts
        self.timestamps.extend(vec![B32::ONE; data.len()]);
    }
    fn get_power(&self, index: u32) -> B32 {
        self.powers[index as usize]
    }
    pub fn process_timestamp(&mut self, index: u32) -> B32 {
        let ts = self.timestamps[index as usize];
        self.timestamps[index as usize] *= B32::MULTIPLICATIVE_GENERATOR;
        ts
    }
    pub fn to_mult(&self, index: u32) -> B32 {
        assert!((index as usize) < self.len());
        self.get_power(index)
    }
    pub fn pad(&mut self) {
        let target_length = self.len().next_power_of_two();
        let padding = vec![0x0; target_length - self.len()];
        self.append(&padding);
    }
}
impl std::ops::Index<u32> for Memory {
    type Output = u8;
    fn index(&self, index: u32) -> &Self::Output {
        &self.mem[index as usize]
    }
}
impl std::ops::Index<std::ops::Range<u32>> for Memory {
    type Output = [u8];
    fn index(&self, index: std::ops::Range<u32>) -> &Self::Output {
        &self.mem[index.start as usize..index.end as usize]
    }
}

// KECCAK-F
pub const HASH_B: usize = 1600 >> 3;
pub const HASH_R: usize = 1088 >> 3;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// chatgpt written
fn rot(x: u64, n: u64) -> u64 {
    let n = n & 0x3F; // mask the rotation amount to 6 bits (0-63)
    (x << n) | (x >> (64 - n))
}

// chatgpt written
fn to_lanes(input: &[u8]) -> Vec<Vec<u64>> {
    (0..5)
        .map(|j| {
            (0..5)
                .map(|i| {
                    let start = (i * 5 + j) << 3;
                    let bytes = &input[start..start + 8];
                    u64::from_le_bytes(bytes.try_into().expect("slice with incorrect length"))
                })
                .collect()
        })
        .collect()
}

// chatgpt written
fn from_lanes(state: &[Vec<u64>]) -> Vec<u8> {
    (0..(1600 >> 3))
        .map(|i| {
            let lane = state[(i >> 3) % 5][(i >> 3) / 5];
            ((lane >> ((i & 0x07) << 3)) & 0xFF) as u8
        })
        .collect()
}

// chatgpt written
pub fn keccak_f(perm_input: [u8; HASH_B]) -> [u8; HASH_B] {
    assert_eq!(perm_input.len(), HASH_B);

    let mut lanes = to_lanes(&perm_input);

    ROUND_CONSTANTS.iter().for_each(|&round_const| {
        // Step 1: Calculate C
        let c: Vec<u64> = (0..5)
            .map(|x| lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4])
            .collect();

        // Step 2: Calculate D
        let d: Vec<u64> = (0..5)
            .map(|x| c[(x + 4) % 5] ^ rot(c[(x + 1) % 5], 1))
            .collect();

        // Step 3: XOR lanes with D
        for x in 0..5 {
            for y in 0..5 {
                lanes[x][y] ^= d[x];
            }
        }

        // Step 4: Apply the rotation and shifting
        let mut b = vec![vec![0u64; 5]; 5];
        let mut x = 1;
        let mut y = 0;
        for t in 0..24 {
            b[y][(2 * x + 3 * y) % 5] = rot(lanes[x][y], (t + 1) * (t + 2) / 2);
            let new_x = y;
            y = (2 * x + 3 * y) % 5;
            x = new_x;
        }
        b[0][0] = lanes[0][0]; // B[0][0] is not rotated

        // Step 5: Apply the non-linear step to lanes
        lanes = (0..5)
            .map(|x| {
                (0..5)
                    .map(|y| b[x][y] ^ (!b[(x + 1) % 5][y] & b[(x + 2) % 5][y]))
                    .collect()
            })
            .collect();

        // Step 6: XOR with round constant
        lanes[0][0] ^= round_const;
    });

    // Convert back to bytes
    let perm_output = from_lanes(&lanes);

    perm_output.try_into().unwrap()
}

// other stuff

pub fn parity_to_field(parity: bool) -> B1 {
    match parity {
        true => B1::ONE,
        false => B1::ZERO,
    }
}

lazy_static::lazy_static! {
    pub static ref U8_TO_MULT_MAP: [B8; 256] = {
        let mut u8_to_mult_map = [B8::ZERO; 256];
        (0..256).fold(B8::ONE, |acc, j| {
            u8_to_mult_map[j] = acc;
            acc * B8::MULTIPLICATIVE_GENERATOR
        });
        u8_to_mult_map
    };
}

pub(crate) fn basis(stride: usize, index: usize) -> B128 {
    <B128 as ExtensionField<BinaryField1b>>::basis(stride * index).unwrap()
}

// macros
pub(crate) mod macros {
    macro_rules! populate_committed_polys {
        ($par_data_iter:ident, $witness:ident, [$(($ident:ident, $type:ty)),* $(,)?]) => {{
            // use rayon::prelude::*;
            (
                $par_data_iter,
                $(
                    $witness.new_column::<$type>($ident).as_mut_slice::<$type>(),
                )*
            )
            .into_par_iter()
            .for_each(
                |(data, $( $ident ),*)| {
                    $(
                        *$ident = data.$ident;
                    )*
                },
            );
        }};
    }
    pub(crate) use populate_committed_polys;

    macro_rules! populate_committed_polys_with_default {
        ($par_data_iter:ident, $witness:ident, [$(($ident:ident, $type:ty, $default:expr)),* $(,)?]) => {{
            // use rayon::prelude::*;
            (
                $par_data_iter,
                $(
                    $witness.new_column_with_default::<$type>($ident, $default).as_mut_slice::<$type>(),
                )*
            )
            .into_par_iter()
            .for_each(
                |(data, $( $ident ),*)| {
                    $(
                        *$ident = data.$ident;
                    )*
                },
            );
        }};
    }
    pub(crate) use populate_committed_polys_with_default;
}

// bit vector
pub(crate) struct BitVec {
    data: Vec<u8>,
    bit_count: usize,
}
impl BitVec {
    pub fn new(initial_capacity: Option<usize>) -> Self {
        Self {
            // capacity is ceil(initial_capacity / 8)
            data: Vec::with_capacity((initial_capacity.unwrap_or(0) + 7) / 8),
            bit_count: 0,
        }
    }

    pub fn _bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn push(&mut self, bit: bool) {
        if self.bit_count % 8 == 0 {
            self.data.push(0);
        }

        if bit {
            let byte_index = self.bit_count / 8;
            // fill bits from LSB to MSB!
            let bit_index = self.bit_count % 8;
            self.data[byte_index] |= 1 << bit_index;
        }

        self.bit_count += 1;
    }
}

impl IntoParallelIterator for BitVec {
    type Item = u8;
    type Iter = rayon::vec::IntoIter<Self::Item>;

    fn into_par_iter(self) -> Self::Iter {
        self.data.into_par_iter()
    }
}

pub struct BitIterator<'a> {
    bytes: &'a [u8],
    bit_index: usize,
    total_bits: usize,
}

impl<'a> BitIterator<'a> {
    pub fn new(bytes: &'a [u8], total_bits: Option<usize>) -> Self {
        Self {
            bytes,
            bit_index: 0,
            total_bits: total_bits.unwrap_or(bytes.len() * 8), // Default to all bits in the slice
        }
    }
}

impl Iterator for BitIterator<'_> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit_index >= self.total_bits {
            return None;
        }
        let byte_index = self.bit_index / 8;
        let bit_position = self.bit_index % 8;
        let bit = (self.bytes[byte_index] & (1 << bit_position)) != 0;
        self.bit_index += 1;
        Some(bit)
    }
}

// transparents

pub(crate) fn make_transparent<FS>(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    name: impl ToString,
    values: &[FS],
) -> Result<OracleId, anyhow::Error>
where
    U: PackScalar<FS>,
    B128: ExtensionField<FS>,
    FS: Pod + TowerField,
{
    let mut packed_values =
        vec![PackedType::<U, FS>::default(); values.len().div_ceil(PackedType::<U, FS>::WIDTH)];
    for (i, value) in values.iter().enumerate() {
        binius_field::packed::set_packed_slice(&mut packed_values, i, *value);
    }

    let poly = binius_core::transparent::multilinear_extension::MultilinearExtensionTransparent::<
        _,
        PackedType<U, B128>,
        _,
    >::from_values(packed_values.clone())
    .unwrap();

    let out = builder.add_transparent(name, poly).unwrap();
    if let Some(witness) = builder.witness() {
        witness
            .new_column::<FS>(out)
            .packed()
            .copy_from_slice(&packed_values);
    }
    Ok(out)
}

// utilities for reading from ROM
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_const(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    name: impl ToString,
    ptr: OracleId,
    val: B8,
    ts: OracleId,
    n_vars: usize,
    count: usize,
    mem_channel_id: usize,
) -> Result<(), anyhow::Error> {
    let vals = builder
        .witness()
        .map(|witness| {
            Ok::<_, anyhow::Error>(
                witness
                    .get::<B32>(ptr)?
                    .as_slice::<u32>()
                    .into_par_iter()
                    .map(|ptr| (val.to_underlier() as u128) << 32 | (*ptr as u128)),
            )
        })
        .transpose()?;

    one_block_rom(
        builder,
        name,
        ts,
        n_vars,
        count,
        [(ptr, basis(32, 0))],
        Some(val * basis(32, 1)),
        vals,
        mem_channel_id,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read_mem_with_nibbles(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    name: impl ToString,
    ptr: OracleId,
    low_nib: OracleId,
    high_nib: OracleId,
    ts: OracleId,
    n_vars: usize,
    count: usize,
    mem_channel_id: usize,
) -> Result<(), anyhow::Error> {
    let vals = builder
        .witness()
        .map(|witness| {
            Ok::<_, anyhow::Error>(
                (
                    witness.get::<B32>(ptr)?.as_slice::<u32>(),
                    witness.get::<B8>(low_nib)?.as_slice::<u8>(),
                    witness.get::<B8>(high_nib)?.as_slice::<u8>(),
                )
                    .into_par_iter()
                    .map(|(ptr, low_nib, high_nib)| {
                        (*high_nib as u128) << (32 + 4) | (*low_nib as u128) << 32 | (*ptr as u128)
                    }),
            )
        })
        .transpose()?;

    one_block_rom(
        builder,
        name,
        ts,
        n_vars,
        count,
        [
            (ptr, basis(32, 0)),
            (low_nib, basis(32, 1)),
            (high_nib, basis(36, 1)),
        ],
        None,
        vals,
        mem_channel_id,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read_mem(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    name: impl ToString,
    ptr: OracleId,
    val: OracleId,
    ts: OracleId,
    n_vars: usize,
    count: usize,
    mem_channel_id: usize,
) -> Result<(), anyhow::Error> {
    let vals = builder
        .witness()
        .map(|witness| {
            Ok::<_, anyhow::Error>(
                (
                    witness.get::<B32>(ptr)?.as_slice::<u32>(),
                    witness.get::<B8>(val)?.as_slice::<u8>(),
                )
                    .into_par_iter()
                    .map(|(ptr, val)| (*val as u128) << 32 | (*ptr as u128)),
            )
        })
        .transpose()?;

    one_block_rom(
        builder,
        name,
        ts,
        n_vars,
        count,
        [(ptr, basis(32, 0)), (val, basis(32, 1))],
        None,
        vals,
        mem_channel_id,
    )?;

    Ok(())
}

//
#[allow(clippy::too_many_arguments)]
pub(crate) fn one_block_rom<Vals>(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    name: impl ToString,
    ts: OracleId,
    n_vars: usize,
    count: usize,
    val_ids: impl IntoIterator<Item = (OracleId, B128)>,
    offset: Option<B128>,
    mut vals: Option<Vals>,
    channel_id: usize,
) -> Result<(), anyhow::Error>
where
    Vals: IntoParallelIterator<Item = u128>,
    Vals::Iter: IndexedParallelIterator,
{
    let val_ids = val_ids.into_iter().collect::<Vec<_>>();
    let mut read_val_ids = val_ids.clone();
    read_val_ids.push((ts, basis(32, 2)));
    let mut write_val_ids = val_ids;
    write_val_ids.push((ts, basis(32, 2) * B32::MULTIPLICATIVE_GENERATOR));

    // from channel_id push (val, ts)
    let read_block = builder.add_linear_combination_with_offset(
        format!("read {}", name.to_string()),
        n_vars,
        offset.unwrap_or(B128::zero()),
        read_val_ids,
    )?;
    builder.receive(channel_id, count, [read_block]);

    // to channel_id push (val, ts * g)
    let write_block = builder.add_linear_combination_with_offset(
        format!("write {}", name.to_string()),
        n_vars,
        offset.unwrap_or(B128::zero()),
        write_val_ids,
    )?;
    builder.send(channel_id, count, [write_block]);

    if let Some(witness) = builder.witness() {
        let vals = vals.take().expect("oops");
        (
            witness
                .new_column::<B128>(read_block)
                .as_mut_slice::<u128>(),
            witness
                .new_column::<B128>(write_block)
                .as_mut_slice::<u128>(),
            witness.get::<B32>(ts)?.as_slice::<B32>(),
            vals,
        )
            .into_par_iter()
            .for_each(|(read_block, write_block, ts, val)| {
                *read_block = ((*ts).to_underlier() as u128) << 64 | val;
                let incremented_ts = (*ts) * B32::MULTIPLICATIVE_GENERATOR;
                *write_block = (incremented_ts.to_underlier() as u128) << 64 | val;
            });
    }

    // enable once padding in place
    builder.assert_not_zero(ts);

    Ok(())
}

// (state_start_ptr, state_key_ptr_byte, state_rlp_ptr, state_ts; state_key_ptr_parity)
#[allow(clippy::too_many_arguments)]
pub fn flush_state(
    builder: &mut ConstraintSystemBuilder<U, B128>,
    flush_direction: FlushDirection,
    start_ptr: OracleId,
    key_ptr_byte: OracleId,
    rlp_ptr: OracleId,
    ts: OracleId,
    key_ptr_parity: OracleId,
    n_vars: usize,
    count: usize,
    state_channel_id: usize,
) -> Result<(), anyhow::Error> {
    builder.push_namespace("flush state");

    let block0 = builder.add_linear_combination(
        "state",
        n_vars,
        [
            (start_ptr, basis(32, 0)),
            (key_ptr_byte, basis(32, 1)),
            (rlp_ptr, basis(32, 2)),
            (ts, basis(32, 3)),
        ],
    )?;
    if let Some(witness) = builder.witness() {
        (
            witness.new_column::<B128>(block0).as_mut_slice::<u128>(),
            witness.get::<B32>(start_ptr)?.as_slice::<u32>(),
            witness.get::<B32>(key_ptr_byte)?.as_slice::<u32>(),
            witness.get::<B32>(rlp_ptr)?.as_slice::<u32>(),
            witness.get::<B32>(ts)?.as_slice::<u32>(),
        )
            .into_par_iter()
            .for_each(|(block, start_ptr, key_ptr_byte, rlp_ptr, ts)| {
                *block = (*ts as u128) << 96
                    | (*rlp_ptr as u128) << 64
                    | (*key_ptr_byte as u128) << 32
                    | (*start_ptr as u128);
            });
    }

    builder.flush(
        flush_direction,
        state_channel_id,
        count,
        [block0, key_ptr_parity],
    );

    builder.pop_namespace();
    Ok(())
}

pub fn verify_mem_read(addr_val_pair: (B32, u8), mem_channel_id: usize) -> [Boundary<B128>; 2] {
    let addr = addr_val_pair.0;
    let val = addr_val_pair.1;
    let read = Boundary {
        values: vec![
            addr * basis(32, 0)
                + B8::from_underlier(val) * basis(32, 1)
                + B32::one() * basis(32, 2),
        ],
        channel_id: mem_channel_id,
        direction: FlushDirection::Pull,
        multiplicity: 1,
    };
    let write = Boundary {
        values: vec![
            addr * basis(32, 0)
                + B8::from_underlier(val) * basis(32, 1)
                + B32::MULTIPLICATIVE_GENERATOR * basis(32, 2),
        ],
        channel_id: mem_channel_id,
        direction: FlushDirection::Push,
        multiplicity: 1,
    };
    [read, write]
}
