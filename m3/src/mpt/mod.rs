// Copyright 2024 Irreducible Inc.

use super::*;

mod build;
mod process_account_proofs;

#[derive(strum_macros::Display, Debug, Clone, Copy)]
pub(crate) enum NodeKind {
    Branch,
    ExtLeaf,
}

type Hash = [u8; 32];

#[derive(Debug)]
pub(crate) struct NodeInfo {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kind: NodeKind,
    pub(crate) position: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct NibPtr {
    pub byte: u32,
    pub parity: bool,
}
impl NibPtr {
    pub fn new(byte: u32, parity: bool) -> Self {
        Self { byte, parity }
    }
}

#[derive(Debug, Serialize, Deserialize)] // do we really need this?
pub(crate) struct AddrValPair {
    address: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)] // for now
pub(crate) struct PtrTsPair {
    rlp_ptr: u32,
    final_ts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TableHeight {
    pub(crate) n_vars: usize,
    pub(crate) count: usize,
}

impl From<&TableHeight> for (usize, usize) {
    fn from(value: &TableHeight) -> (usize, usize) {
        (value.n_vars, value.count)
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum TableType {
    SkipListHeader,
    KeccakF,
    AbsorbBlockBase,
    AbsorbBlockRecursive,
    HashTransTable,
    GetChildBase,
    GetChildRecursive,
    BranchTrans,
    ExtLeafTrans,
    CheckNibBase,
    CheckNibRecursive,
    ForkStableTable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TableHeights {
    skip_list_header: TableHeight,
    keccak_f: TableHeight,
    absorb_block_base_table: TableHeight,
    absorb_block_recursive_table: TableHeight,
    hash_trans_table: TableHeight,
    get_child_base_table: TableHeight,
    get_child_recursive_table: TableHeight,
    branch_trans_table: TableHeight,
    ext_leaf_trans_table: TableHeight,
    check_nib_base_table: TableHeight,
    check_nib_recursive_table: TableHeight,
    fork_state_table: TableHeight,
    populate_mem: usize,
}

impl TableHeights {
    pub(crate) fn as_list(&self) -> HashMap<TableType, (usize, usize)> {
        let Self {
            skip_list_header,
            keccak_f,
            absorb_block_base_table,
            absorb_block_recursive_table,
            hash_trans_table,
            get_child_base_table,
            get_child_recursive_table,
            branch_trans_table,
            ext_leaf_trans_table,
            check_nib_base_table,
            check_nib_recursive_table,
            fork_state_table,
            populate_mem: _,
        } = &self;
        HashMap::from([
            (TableType::SkipListHeader, skip_list_header.into()),
            (TableType::KeccakF, keccak_f.into()),
            (TableType::AbsorbBlockBase, absorb_block_base_table.into()),
            (
                TableType::AbsorbBlockRecursive,
                absorb_block_recursive_table.into(),
            ),
            (TableType::HashTransTable, hash_trans_table.into()),
            (TableType::GetChildBase, get_child_base_table.into()),
            (
                TableType::GetChildRecursive,
                get_child_recursive_table.into(),
            ),
            (TableType::BranchTrans, branch_trans_table.into()),
            (TableType::ExtLeafTrans, ext_leaf_trans_table.into()),
            (TableType::CheckNibBase, check_nib_base_table.into()),
            (
                TableType::CheckNibRecursive,
                check_nib_recursive_table.into(),
            ),
            (TableType::ForkStableTable, fork_state_table.into()),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Advice {
    ptr_ts_pairs: Vec<PtrTsPair>,
    pub(crate) table_heights: TableHeights,
}
// statement is the root hash with a list of address, value pairs..
// where value is the leaf value, which for account proofs equals
// the rlp encoding of the list of (nonce, balance, storage_root, code_hash)
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Statement {
    root_hash: Hash,
    addr_val_pairs: Vec<AddrValPair>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct State {
    pub start_ptr: u32,
    pub key_ptr: NibPtr,
    pub rlp_ptr: u32,
    pub ts: B32,
}
impl State {
    fn all_but_ts_eq(left_state: &State, right_state: &State) -> bool {
        left_state.start_ptr == right_state.start_ptr
            && left_state.key_ptr == right_state.key_ptr
            && left_state.rlp_ptr == right_state.rlp_ptr
    }
}

// map from key to node info list
pub(crate) type ProofData = std::collections::HashMap<usize, Vec<NodeInfo>>;

#[repr(C)]
pub(crate) struct ChannelIds {
    pub mem: ChannelId,
    pub state: ChannelId,
    pub skip_list_header: ChannelId,
    pub skip_list_header_offset_lookup: ChannelId,
    pub keccak_f: ChannelId,
    pub absorb_block: ChannelId,
    pub get_child: ChannelId,
    pub get_child_offset_lookup: ChannelId,
    pub branch_trans_shift_lookup: ChannelId,
    pub check_nib: ChannelId,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Action {
    Ignore,
    Count,
    Append,
}

#[allow(clippy::upper_case_acronyms)]
pub struct MPT {
    pub(crate) state: MPTState,
    statement: Statement,
    keys: Vec<Hash>,
    proof_data: Option<ProofData>,

    // tables
    pub(crate) skip_list_header_table: SkipListHeaderTable,
    pub(crate) skip_list_header_count: usize,
    pub(crate) skip_list_header_offset_lookup_table: SkipListHeaderOffsetLookupTable,
    pub(crate) keccak_f_table: KeccakFTable,
    pub(crate) keccak_f_count: usize,
    pub(crate) absorb_block_base_table: AbsorbBlockBaseTable,
    pub(crate) absorb_block_base_count: usize,
    pub(crate) absorb_block_recursive_table: AbsorbBlockRecursiveTable,
    pub(crate) absorb_block_recursive_count: usize,
    pub(crate) hash_trans_table: HashTransTable,
    pub(crate) hash_trans_count: usize,
    pub(crate) get_child_base_table: GetChildBaseTable,
    pub(crate) get_child_base_count: usize,
    pub(crate) get_child_recursive_table: GetChildRecursiveTable,
    pub(crate) get_child_recursive_count: usize,
    pub(crate) get_child_offset_lookup_table: GetChildOffsetLookupTable,
    pub(crate) branch_trans_table: BranchTransTable,
    pub(crate) branch_trans_count: usize,
    pub(crate) branch_trans_shift_lookup_table: BranchTransShiftLookupTable,
    pub(crate) ext_leaf_trans_table: ExtLeafTransTable,
    pub(crate) ext_leaf_trans_count: usize,
    pub(crate) check_nib_base_table: CheckNibBaseTable,
    pub(crate) check_nib_base_count: usize,
    pub(crate) check_nib_recursive_table: CheckNibRecursiveTable,
    pub(crate) check_nib_recursive_count: usize,
    pub(crate) fork_state_table: ForkStateTable,
    pub(crate) fork_state_count: usize,
    pub(crate) populate_mem_table: PopulateMemTable,
}
impl MPT {
    #[instrument(name = "new MPT", skip_all, level = "debug")]
    pub fn new(statement: Statement) -> Self {
        let keys: Vec<Hash> = statement
            .addr_val_pairs
            .iter()
            .map(|addr_val_pair| keccak256(&addr_val_pair.address).into())
            .collect();

        Self {
            state: MPTState {
                mem: Memory::new(),
                skip_list_header_offset_lookup: SkipListHeaderOffsetLookup::new(),
                get_child_offset_lookup: GetChildOffsetLookup::new(),
                branch_trans_shift_lookup: BranchTransShiftLookup::new(),
                state_final_tss: HashMap::new(),
            },
            statement,
            keys,
            proof_data: None,
            // tables than impl FunctionTable (12 of these)
            skip_list_header_table: SkipListHeaderTable::new(),
            skip_list_header_count: 0,
            keccak_f_table: KeccakFTable::new(),
            keccak_f_count: 0,
            absorb_block_base_table: AbsorbBlockBaseTable::new(),
            absorb_block_base_count: 0,
            absorb_block_recursive_table: AbsorbBlockRecursiveTable::new(),
            absorb_block_recursive_count: 0,
            hash_trans_table: HashTransTable::new(),
            hash_trans_count: 0,
            get_child_base_table: GetChildBaseTable::new(),
            get_child_base_count: 0,
            get_child_recursive_table: GetChildRecursiveTable::new(),
            get_child_recursive_count: 0,
            branch_trans_table: BranchTransTable::new(),
            branch_trans_count: 0,
            ext_leaf_trans_table: ExtLeafTransTable::new(),
            ext_leaf_trans_count: 0,
            check_nib_base_table: CheckNibBaseTable::new(),
            check_nib_base_count: 0,
            check_nib_recursive_table: CheckNibRecursiveTable::new(),
            check_nib_recursive_count: 0,
            fork_state_table: ForkStateTable::new(),
            fork_state_count: 0,
            // table to populate memory
            populate_mem_table: PopulateMemTable::new(),
            // tables to populate lookups
            skip_list_header_offset_lookup_table: SkipListHeaderOffsetLookupTable::new(),
            get_child_offset_lookup_table: GetChildOffsetLookupTable::new(),
            branch_trans_shift_lookup_table: BranchTransShiftLookupTable::new(),
        }
    }
}

impl MPT {
    fn skip_short_byte_string(&self, ptr: u32) -> u32 {
        let val = self.state.mem[ptr];
        debug_assert!((128..184).contains(&val));
        let length = self.state.mem[ptr] - 128;
        ptr + 1 + length as u32
    }

    pub(crate) fn increment(key_ptr: NibPtr) -> NibPtr {
        match key_ptr.parity {
            true => NibPtr {
                byte: key_ptr.byte + 1,
                parity: false,
            },
            false => NibPtr {
                byte: key_ptr.byte,
                parity: true,
            },
        }
    }

    pub(crate) fn skip_list(&self, ptr: u32) -> u32 {
        let u8_val = self.state.mem[ptr];
        debug_assert!(192 <= u8_val);
        if u8_val < 248 {
            return ptr + 1 + u8_val as u32 - 192;
        }
        let len_len = u8_val - 247;
        let bytes_len = &self.state.mem[ptr + 1..ptr + 1 + len_len as u32];
        fn to_u128_big_endian(slice: &[u8]) -> u128 {
            let mut result = 0;
            for &byte in slice {
                result = (result << 8) | byte as u128
            }
            result
        }
        let len = to_u128_big_endian(bytes_len);
        ptr + 1 + len_len as u32 + len as u32
    }
}

pub(crate) struct MPTState {
    pub(crate) mem: Memory,
    pub(crate) skip_list_header_offset_lookup: SkipListHeaderOffsetLookup,
    pub(crate) get_child_offset_lookup: GetChildOffsetLookup,
    pub(crate) branch_trans_shift_lookup: BranchTransShiftLookup,
    pub(crate) state_final_tss: HashMap<u32, B32>,
}

pub(crate) trait FunctionTable {
    type Data;
    fn new() -> Self;
    fn allocate(&mut self, count: usize) -> usize;
    fn append(&mut self, mpt_state: &mut MPTState, data: Self::Data);
    fn build(
        self,
        builder: &mut ConstraintSystemBuilder<U, B128>,
        channel_ids: &ChannelIds,
        table_height: TableHeight,
    ) -> Result<(), anyhow::Error>;
}

#[instrument(name = "get_statement_and_account_proofs", fields(alloy_account_proof_count = alloy_account_proofs.len()), skip_all, level = "debug")]
pub fn get_statement_and_account_proofs(
    alloy_account_proofs: Vec<EIP1186AccountProofResponse>,
) -> (Statement, Vec<AccountProof>) {
    let account_proofs = alloy_account_proofs
        .into_iter()
        .map(|proof| {
            let x = proof
                .account_proof
                .into_iter()
                .map(|node| node.to_vec())
                .collect::<Vec<_>>();
            AccountProof {
                address: proof.address,
                nodes: x,
            }
        })
        .collect::<Vec<_>>();

    let root_hash = {
        let first_account_proof = &account_proofs[0];
        let first_node = &first_account_proof.nodes[0];
        let rlp = keccak256(first_node).to_vec();
        rlp.try_into().expect("keccak hash output is 32 bytes")
    };

    let addr_val_pairs = account_proofs
        .iter()
        .map(|account_proof| {
            let leaf_node = account_proof.nodes.last().expect("shoudn't be empty");
            let mut decoded = rlp_decode_node(&mut leaf_node.as_ref());
            debug_assert_eq!(decoded.len(), 2);
            let leaf_val_bytes = decoded.pop().expect("msg");
            // this is the true 'item', without the rlp encoding
            AddrValPair {
                address: account_proof.address.to_vec(),
                value: leaf_val_bytes,
            }
        })
        .collect::<Vec<_>>();

    let statement = Statement {
        root_hash,
        addr_val_pairs,
    };

    (statement, account_proofs)
}

// rlp stuff
fn rlp_decode_node(node: &mut &[u8]) -> Vec<Vec<u8>> {
    let bytes_list = Vec::<Bytes>::decode(node).unwrap();
    let bytes_list = bytes_list.iter().map(|bytes| bytes.to_vec()).collect();
    bytes_list
}

fn rlp_encode_long_bytestring(bytestring: &[u8]) -> Vec<u8> {
    let length = bytestring.len();
    // convert the usize to bytes
    let bytes = length.to_le_bytes();
    // trim leading zeros
    let ell_prime = bytes.iter().rev().skip_while(|&&b| b == 0).count() as u8;

    let mut rlp_bytes = vec![ell_prime + 183];
    (0..ell_prime).for_each(|i| {
        rlp_bytes.push(bytes[i as usize]);
    });
    rlp_bytes.extend(bytestring);
    rlp_bytes
}
