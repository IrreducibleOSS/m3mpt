# m3mpt

This project builds a [Binius](https://github.com/IrreducibleOSS/binius) binary proof for compressing [Merkle Patricia Trie](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/) (MPT) inclusion proofs. Irreducible runs a [hosted service](https://www.irreducible.com/posts/ethereum-state-proving-service) that generates and publishes these proofs to Amazon S3. The service processes each Ethereum block in real time and publishes an inclusion proof for all accounts read during block execution.

For a summary of how the constraint system in this repo arithmetizes MPT inclusion proofs, see [MPT Inclusion](https://www.binius.xyz/basics/arithmetization/mpt) arithmetization.

## Verifying Published Proofs

The CLI module is used to verify a published MPT proof, given an Ethereum block hash.

Usage example:
```sh
cargo run --release -- --block 0xef9a95bfef8e783ddec5301b9ac438c5dc7282430c37ac7ac8cfeca265436f2c
```

## M3 module

In `m3` the constraint system is built and tested.
Run

```rs
cargo test --release test_prove_verify_cpu_76_testnet --nocapture
```

to test proving 76 inclusion proofs for the Ethereum Holesky testnet.
Or to test 450 inclusion proofs for the Ethereum mainnet run

```rs
cargo test --release test_prove_verify_cpu_450_mainnet -- --include-ignored --nocapture
```

Testing without running in release mode will likely be too slow.
The flag `--nocapture` allows for printing tracing information to give you an idea of the steps taken during proving and verification and their relative times. This tracing is done using [tracing profile](https://github.com/IrreducibleOSS/tracing-profile).

## References

For a summary of working with the [Binius constraint system](https://docs.binius.xyz/binius_core/constraint_system/index.html) see [Building on Binius](https://www.binius.xyz/building/).

## Authors

Binius is developed by [Irreducible](https://www.irreducible.com).

## License

Copyright 2024-2025 Irreducible Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
