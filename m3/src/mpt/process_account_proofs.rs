// Copyright 2024 Irreducible Inc.

use super::*;

impl MPT {
    #[instrument(name = "process_account_proofs", fields(account_proof_count = account_proofs.len()), skip_all, level = "debug")]
    pub fn process_account_proofs(&mut self, account_proofs: Vec<AccountProof>) -> Advice {
        self.initialize_prover(account_proofs);
        let leaf_rlp_ptr_len_pairs = self.get_leaf_rlp_ptr_len_pairs();

        let mut hashes_visited = HashSet::new();
        let mut nodes_visited = HashMap::new();

        self.process_phase(true, &mut hashes_visited, &mut nodes_visited);
        let table_heights = self.allocate_for_function_tables();
        hashes_visited.clear();
        self.reset_function_table_counters();
        self.simulate_verifier_mem_reading(&leaf_rlp_ptr_len_pairs);
        self.process_phase(false, &mut hashes_visited, &mut nodes_visited);
        self.populate_lookup_tables();
        let ptr_ts_pairs = self.get_ptr_ts_pairs(&leaf_rlp_ptr_len_pairs);

        Advice {
            ptr_ts_pairs,
            table_heights,
        }
    }

    // create proof_data, and insert everything (root hash, keys, and all nodes) into memory
    #[instrument(name = "initialize_prover", skip_all level = "debug")]
    fn initialize_prover(&mut self, account_proofs: Vec<AccountProof>) {
        assert_eq!(account_proofs.len(), self.keys.len());
        // append root hash rlp to mem
        let mut root_hash_rlp = vec![0xa0];
        root_hash_rlp.extend(self.statement.root_hash);
        self.state.mem.append(&root_hash_rlp);
        // append keys to mem
        self.keys.iter().for_each(|key| self.state.mem.append(key));
        // append all nodes to mem and get proof_data
        self.proof_data = Some(self.setup_proof_data(account_proofs));
        // pad mem
        self.state.mem.pad();
    }

    // generate proof_data and append all rlp-encoded nodes into mem
    #[instrument(skip_all, name = "setup_proof_data", level = "debug")]
    fn setup_proof_data(&mut self, account_proofs: Vec<AccountProof>) -> ProofData {
        // a map from nodes to their positions in mem
        let mut nodes_visited: HashMap<Vec<u8>, u32> = HashMap::new();
        let mut proof_data = HashMap::new();

        for (i, account_proof) in account_proofs.into_iter().enumerate() {
            let node_info_list: Vec<NodeInfo> = account_proof
                .nodes
                .into_iter()
                .map(|node_bytes| {
                    let entry = nodes_visited.entry(node_bytes.clone());
                    // if node visited, return the position; if not get next position by cursor and insert into visited_nodes
                    let position = *entry.or_insert_with(|| {
                        let position = self.state.mem.cursor();
                        self.state.mem.append(&node_bytes);
                        let padding = MPT::get_padding_bytes(node_bytes.len());
                        self.state.mem.append(&padding);
                        position
                    });
                    let node_kind = match rlp_decode_node(&mut node_bytes.as_slice()).len() {
                        2 => NodeKind::ExtLeaf,
                        17 => NodeKind::Branch,
                        _ => unreachable!(),
                    };
                    NodeInfo {
                        bytes: node_bytes,
                        kind: node_kind,
                        position,
                    }
                })
                .collect();

            proof_data.insert(i, node_info_list);
        }
        proof_data
    }

    fn get_padding_bytes(bytes_lenght: usize) -> Vec<u8> {
        let total_blocks = bytes_lenght / HASH_R + 1;
        let padding_width = total_blocks * HASH_R - bytes_lenght;
        let mut padding: Vec<u8> = vec![0; padding_width];
        match padding_width {
            1 => {
                padding[0] = 0x81;
            }
            _ => {
                padding[0] = 0x01;
                padding[padding_width - 1] = 0x80;
            }
        };
        padding
    }

    fn first_phase_trans(
        &mut self,
        trans_func: fn(&mut MPT, Action, State) -> State,
        node_info: &NodeInfo,
        state: State,
        hashes_visited: &mut HashSet<u32>,
        nodes_visited: &mut HashMap<u32, State>,
    ) -> State {
        let mid_state = self.hash_trans(Action::Ignore, node_info.position, state);
        let new_state = trans_func(self, Action::Ignore, mid_state);
        if hashes_visited.contains(&new_state.rlp_ptr) {
            return new_state;
        }
        hashes_visited.insert(new_state.rlp_ptr);

        if let Some(saved_mid_state) = nodes_visited.get_mut(&mid_state.rlp_ptr) {
            self.fork_state(Action::Count, *saved_mid_state, state.start_ptr);
            saved_mid_state.ts *= B32::MULTIPLICATIVE_GENERATOR;
        } else {
            self.hash_trans(Action::Count, node_info.position, state);
            nodes_visited.insert(mid_state.rlp_ptr, mid_state);
        }
        trans_func(self, Action::Count, mid_state)
    }

    fn second_phase_trans(
        &mut self,
        trans_func: fn(&mut MPT, Action, State) -> State,
        node_info: &NodeInfo,
        state: State,
        hashes_visited: &mut HashSet<u32>,
        nodes_visited: &mut HashMap<u32, State>,
    ) -> State {
        // identical to the first block in the first phase, maybe extract out to remove duplication
        let mut mid_state = self.hash_trans(Action::Ignore, node_info.position, state);
        let mut new_state = trans_func(self, Action::Ignore, mid_state);
        if hashes_visited.contains(&new_state.rlp_ptr) {
            return new_state;
        }
        hashes_visited.insert(new_state.rlp_ptr);

        let saved_mid_state = nodes_visited.get_mut(&mid_state.rlp_ptr).unwrap();
        if !State::all_but_ts_eq(saved_mid_state, &mid_state) {
            self.fork_state(Action::Append, *saved_mid_state, state.start_ptr);
            saved_mid_state.ts *= B32::MULTIPLICATIVE_GENERATOR;
        } else {
            self.hash_trans(Action::Append, node_info.position, state);
            let mid_state_ts = mid_state.ts;
            mid_state.ts *= saved_mid_state.ts;
            saved_mid_state.ts = mid_state_ts;
        }
        new_state = trans_func(self, Action::Append, mid_state);

        new_state
    }

    fn process_phase(
        &mut self,
        first_phase: bool,
        hashes_visited: &mut HashSet<u32>,
        nodes_visited: &mut HashMap<u32, State>,
    ) {
        let proof_data = self.proof_data.take().unwrap();

        let root_mem_offset = 0;
        let keys_mem_offset = root_mem_offset + 1 + 32;

        for i in 0..self.keys.len() {
            let start_ptr = keys_mem_offset + i as u32 * 32;
            let key_ptr = NibPtr {
                byte: start_ptr,
                parity: false,
            };
            let mut state = State {
                start_ptr,
                key_ptr,
                rlp_ptr: root_mem_offset,
                ts: B32::ONE,
            };

            for node_info in proof_data.get(&i).unwrap() {
                let phase = match first_phase {
                    true => MPT::first_phase_trans,
                    false => MPT::second_phase_trans,
                };
                match node_info.kind {
                    NodeKind::Branch => {
                        state = (phase)(
                            self,
                            MPT::branch_trans,
                            node_info,
                            state,
                            hashes_visited,
                            nodes_visited,
                        );
                    }
                    NodeKind::ExtLeaf => {
                        state = (phase)(
                            self,
                            MPT::ext_leaf_trans,
                            node_info,
                            state,
                            hashes_visited,
                            nodes_visited,
                        );
                    }
                }
            }
            if !first_phase {
                self.state.state_final_tss.insert(state.rlp_ptr, state.ts);
            }
            assert_eq!(state.key_ptr.byte, start_ptr + 32);
            assert!(!state.key_ptr.parity);
        }

        self.proof_data = Some(proof_data);
    }

    fn reset_function_table_counters(&mut self) {
        self.skip_list_header_count = 0;
        self.keccak_f_count = 0;
        self.absorb_block_base_count = 0;
        self.absorb_block_recursive_count = 0;
        self.hash_trans_count = 0;
        self.get_child_base_count = 0;
        self.get_child_recursive_count = 0;
        self.branch_trans_count = 0;
        self.ext_leaf_trans_count = 0;
        self.check_nib_base_count = 0;
        self.check_nib_recursive_count = 0;
        self.fork_state_count = 0;
    }

    fn allocate_for_function_tables(&mut self) -> TableHeights {
        TableHeights {
            skip_list_header: TableHeight {
                n_vars: self
                    .skip_list_header_table
                    .allocate(self.skip_list_header_count),
                count: self.skip_list_header_count,
            },
            keccak_f: TableHeight {
                n_vars: self.keccak_f_table.allocate(self.keccak_f_count),
                count: self.keccak_f_count,
            },
            absorb_block_base_table: TableHeight {
                n_vars: self
                    .absorb_block_base_table
                    .allocate(self.absorb_block_base_count),
                count: self.absorb_block_base_count,
            },
            absorb_block_recursive_table: TableHeight {
                n_vars: self
                    .absorb_block_recursive_table
                    .allocate(self.absorb_block_recursive_count),
                count: self.absorb_block_recursive_count,
            },
            hash_trans_table: TableHeight {
                n_vars: self.hash_trans_table.allocate(self.hash_trans_count),
                count: self.hash_trans_count,
            },
            get_child_base_table: TableHeight {
                n_vars: self
                    .get_child_base_table
                    .allocate(self.get_child_base_count),
                count: self.get_child_base_count,
            },
            get_child_recursive_table: TableHeight {
                n_vars: self
                    .get_child_recursive_table
                    .allocate(self.get_child_recursive_count),
                count: self.get_child_recursive_count,
            },
            branch_trans_table: TableHeight {
                n_vars: self.branch_trans_table.allocate(self.branch_trans_count),
                count: self.branch_trans_count,
            },
            ext_leaf_trans_table: TableHeight {
                n_vars: self
                    .ext_leaf_trans_table
                    .allocate(self.ext_leaf_trans_count),
                count: self.ext_leaf_trans_count,
            },
            check_nib_base_table: TableHeight {
                n_vars: self
                    .check_nib_base_table
                    .allocate(self.check_nib_base_count),
                count: self.check_nib_base_count,
            },
            check_nib_recursive_table: TableHeight {
                n_vars: self
                    .check_nib_recursive_table
                    .allocate(self.check_nib_recursive_count),
                count: self.check_nib_recursive_count,
            },
            fork_state_table: TableHeight {
                n_vars: self.fork_state_table.allocate(self.fork_state_count),
                count: self.fork_state_count,
            },
            populate_mem: self.state.mem.len().trailing_zeros() as usize,
        }
    }

    fn get_leaf_rlp_ptr_len_pairs(&mut self) -> Vec<(u32, u32)> {
        let proof_data = self.proof_data.take().unwrap();
        let leaf_rlp_ptr_len_pairs = (0..self.keys.len())
            .map(|i| {
                let node_info_list = proof_data.get(&i).unwrap();
                let node_info = node_info_list.last().unwrap();

                let post_leaf_header_ptr = {
                    let list_ptr = node_info.position;
                    let prefix_val = self.state.mem[list_ptr];
                    let offset = MPT::skip_list_header_offset_lookup(prefix_val);
                    list_ptr + offset as u32
                };
                let rlp_ptr = self.skip_short_byte_string(post_leaf_header_ptr);

                let length = {
                    let mut decoded = rlp_decode_node(&mut node_info.bytes.as_ref());
                    assert_eq!(decoded.len(), 2);
                    let leaf_val_bytes = decoded.pop().expect("checked length to be 2");
                    let val = rlp_encode_long_bytestring(&leaf_val_bytes);
                    val.len() as u32
                };

                (rlp_ptr, length)
            })
            .collect::<Vec<_>>();
        self.proof_data = Some(proof_data);
        leaf_rlp_ptr_len_pairs
    }

    fn simulate_verifier_mem_reading(&mut self, leaf_rlp_ptr_len_pairs: &[(u32, u32)]) {
        // root hash rlp prefix
        self.state.mem.process_timestamp(0);
        // root hash
        (0..32).for_each(|index| {
            self.state.mem.process_timestamp(1 + index);
        });
        // all keys
        (0..self.keys.len() * 32).for_each(|index| {
            self.state.mem.process_timestamp(1 + 32 + index as u32);
        });
        // the leaf nodes
        let proof_data = self.proof_data.take().unwrap();
        debug_assert_eq!(leaf_rlp_ptr_len_pairs.len(), self.keys.len());
        leaf_rlp_ptr_len_pairs
            .iter()
            .for_each(|(leaf_rlp_ptr, length)| {
                (0..*length).for_each(|offset| {
                    let index = leaf_rlp_ptr + offset;
                    self.state.mem.process_timestamp(index);
                });
            });
        self.proof_data = Some(proof_data);
    }

    fn get_ptr_ts_pairs(&mut self, leaf_rlp_ptr_len_pairs: &[(u32, u32)]) -> Vec<PtrTsPair> {
        let proof_data = self.proof_data.take().unwrap();
        debug_assert_eq!(leaf_rlp_ptr_len_pairs.len(), self.keys.len());
        let ptr_ts_pairs = leaf_rlp_ptr_len_pairs
            .iter()
            .map(|(leaf_rlp_ptr, _)| {
                let final_ts = self.state.state_final_tss.get(leaf_rlp_ptr).unwrap();
                PtrTsPair {
                    rlp_ptr: *leaf_rlp_ptr,
                    final_ts: final_ts.to_underlier(),
                }
            })
            .collect::<Vec<_>>();
        self.proof_data = Some(proof_data);
        ptr_ts_pairs
    }

    fn populate_lookup_tables(&mut self) {
        self.skip_list_header_offset_lookup_table
            .populate(&mut self.state);
        self.get_child_offset_lookup_table.populate(&mut self.state);
        self.branch_trans_shift_lookup_table
            .populate(&mut self.state);
    }
}
