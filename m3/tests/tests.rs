// Copyright 2024 Irreducible Inc.

use alloy::{
    providers::{Provider, ProviderBuilder},
    rpc::types::EIP1186AccountProofResponse,
};
use binius_hal::make_portable_backend;
use std::fs::File;
use std::future::IntoFuture;
use std::path::PathBuf;
use tracing_profile::init_tracing;

#[test]
fn test_prove_verify_cpu_76_testnet() {
    let account_proofs: Vec<EIP1186AccountProofResponse> =
        bincode::deserialize(include_bytes!("eip1186_proofs_1.bin")).unwrap();
    let _guard = init_tracing().expect("failed to initialize tracing");
    let (proof, _) = binius_mp3::prove(account_proofs, &make_portable_backend()).unwrap();
    binius_mp3::verify(proof).unwrap();
}

#[test]
#[ignore]
fn test_prove_verify_cpu_450_mainnet() {
    let data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mainnet_21367805.json");
    let data_file = File::open(data_path).unwrap();
    let account_proofs: Vec<EIP1186AccountProofResponse> =
        serde_json::from_reader(data_file).unwrap();

    let _guard = init_tracing().expect("failed to initialize tracing");
    let (proof, _) = binius_mp3::prove(account_proofs, &make_portable_backend()).unwrap();
    binius_mp3::verify(proof).unwrap();
}

#[test]
#[ignore]
fn test_prove_verify_cpu_3395_mainnet() {
    let data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mainnet_21572786_3395proofs.json");
    let data_file = File::open(data_path).unwrap();
    let account_proofs: Vec<EIP1186AccountProofResponse> =
        serde_json::from_reader(data_file).unwrap();

    let _guard = init_tracing().expect("failed to initialize tracing");
    let (proof, _) = binius_mp3::prove(account_proofs, &make_portable_backend()).unwrap();
    binius_mp3::verify(proof).unwrap();
}

#[test]
#[ignore = "This is only used for generating test data"]
fn download_test_data() {
    let account_proofs = fetch_eip1186_proofs(&[
        "0xfE921e06Ed0a22c035b4aCFF0A5D3a434A330c96",
        "0xB0343BB9fc6Fe61438E5772200FB41807c84ffC0",
        "0x0000000000000000000000000000000000000007",
        "0x93de6a193A839218BCA00c8D478256Ac78281cE3",
        "0xC6392aD8A14794eA57D237D12017E7295bea2363",
        "0x53668EBf2e28180e38B122c641BC51Ca81088871",
        "0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9",
        "0xf0e53a4814F1Aa8Adc3809d3a527Ae807a140CED",
        "0x854dc9e5d011B060bf77B1a492302C349f2f00b5",
        "0x0000000000000000000000000000000000000005",
        "0x09AfC4c265f22d7e72b7a3c3551CAC4f710114f9",
        "0x9E465102D4A4dA816d9901Ac2eE4db5838deF001",
        "0x335A3C387262Da18DffcfcD9540691F7885272e0",
        "0x63838f721d2f07afF596308BD586b99B75e30f48",
        "0xd1555Be14931C061E06D3CE1D1Daadc1B3c6F8c7",
        "0xd031a54b352e22bdf8F5f2a72bD24c3aE9e7a6b5",
        "0x3aD77134c986193c9ef98e55e800B71e72835b62",
        "0xe200dFf4b35643b5C192F88D607c0e544705794c",
        "0x83730f1AD006dd47ce15ab6C52B2Ee179cf26D8F",
        "0x51E920AeCB95b2d166B6be78cf59358f55959825",
        "0x04Cb2eb2fC7Bd83b197053898313f10541A36D15",
        "0xAd7f9e558170a149Ca8E90f41Ab2444A5d3bd6aD",
        "0x0000000000000000000000000000000000000001",
        "0x51462D5511563A0F97Bb3Ce5475E1c3905b83F4b",
        "0x85a560C3c42Aad2454da880f603FCaE785203193",
        "0x54A03db2784E3D0aCC08344D05385d0b62d4F432",
        "0x4dB947ff52Ec6d847958eCB785D94193FD4C78f6",
        "0xf80f224De3bCebAc1A4A76F6918b42909981c648",
        "0x62bF916d0379E758b6168981882Aa8A121182F1a",
        "0x32778D6bf5b93B89177D328556EeeB35c09f472b",
        "0x815aeCA64a974297942D2Bbf034ABEe22a38A003",
        "0xD7149C166A83D25fE1EaFc8263Ec5A3B9cb29DD1",
        "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02",
        "0x3212C1580A8826BB41E2AE8a3F5B475219E6d741",
        "0xE3122833ac2201B220E4d1A647CC6004E5657010",
        "0x73b2e0E54510239E22cC936F0b4a6dE1acf0AbdE",
        "0x0000000000000000000000000000000000000006",
        "0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548",
        "0x58F280BeBE9B34c9939C3C39e0890C81f163B623",
        "0xe2b344C6077fb9cF3930986e7304E1E350020326",
        "0x29410c27711a610F6484448d42C84f032f4951f1",
        "0xB36Da96dF3e0c214b20d8ae49f4979efddFA61B6",
        "0x482a96D5879e32347d8df125f038D7eC8Ab358dd",
        "0xa35EE02E1E80672d5D89546901B36b6F493CC342",
        "0xe914D607A64c5ac3b2c9db3e1b5D809ec4C2E4BF",
        "0x2c61EA360D6500b58E7f481541A36B443Bc858c6",
        "0xD51322159Ad638f16AA21E9A7b3c2d1035c90F0E",
        "0x56CD23Baaf2e7cb7056968d85E5EFe343b0E1DC2",
        "0xB7549c18b8BbaaCdd6502B5a290195407c5Df29A",
        "0x0000000000000000000000000000000000000008",
        "0x5620cDb94BaAaD10c20483bd8705DA711b2Bc0a3",
        "0x5b08485687672CE6654E037B7026208b5d5C863a",
        "0xD0A725d82649f9e4155D7A60B638Fe33b3F25e3b",
        "0x85977E7AbcF14F1a88E7BD75eB2653a51649c519",
        "0x1616BEF115C8ae69dB330b9A8a901e7Fd16187B0",
        "0xeD8CB658Bc5062f75e036cd8942Da660f9A087B9",
        "0x79E88A7a861395E33325796E58dEe1642f486d57",
        "0x58973d16FFA900D11fC22e5e2B6840d9f7e13401",
        "0x7B65bdfF67E7BD6a777280ca1dC057bF2940bc66",
        "0xB05BB98a966F58aDAB8dF58350b77fF2131A3b87",
        "0xe762416d927100A95A7E307f4679A398f179c5ba",
        "0x07802Aa18a16E6F4d1a3411657a0f6b0a9Cb8Ea1",
        "0x3E3bBF22616a6A87cE8882C83a108bC3ea404c63",
        "0x48d70037cC01c31039d476CbbbAe2Aa36F86Ef16",
        "0x594Fb75D3dc2DFa0150Ad03F99F97817747dd4E1",
        "0xe9a62428d275583F1e3889193c984C2591f16F74",
        "0x1df7be90E3744168f6174805A5f20d4846F9D20b",
        "0x5432214BeE0d8185C3403D9C4DC76601DB4e4468",
        "0x9C70dCF636BE7f76F857e7eC3468A3f0e8CB6Cc3",
        "0xce1D1de6B1ecDE6147DB8E54Cbfa01731d808bdf",
        "0x33C7Fe345CF0E2b1c5c2a576fc91aB1b0aa6c6c7",
        "0x0000000000000000000000000000000000000002",
        "0xAB630768C48Ea979559D475bEB1301680Ca9eE08",
        "0x6b9979588a7598F0Ea377a796Eb2468BCAE6f057",
        "0x6D9A3cA98B8700B76CC350D1Ad5a3fF86a12C306",
        "0xAB17435a759d956B8AA204dB3176b92be94E9B81",
    ])
    .unwrap();

    std::fs::write(
        "tests/eip1186_proofs_1.bin",
        bincode::serialize(&account_proofs).unwrap(),
    )
    .unwrap();
}

pub fn fetch_eip1186_proofs(
    addresses: &[impl AsRef<str>],
) -> Result<Vec<alloy::rpc::types::EIP1186AccountProofResponse>, anyhow::Error> {
    let provider =
        ProviderBuilder::new().on_http("https://ethereum-holesky-rpc.publicnode.com".parse()?);
    let addresses = addresses
        .iter()
        .map(|addr| alloy::primitives::Address::parse_checksummed(addr, None))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(join_all_blocking(
        addresses
            .into_iter()
            .map(|addr| provider.get_proof(addr, vec![])),
    )?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?)
}

fn join_all_blocking<T: IntoFuture>(
    tasks: impl IntoIterator<Item = T>,
) -> Result<Vec<T::Output>, anyhow::Error>
where
    T::Output: Send + 'static,
    T::IntoFuture: Send + 'static,
{
    tokio::runtime::Runtime::new()?.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for task in tasks {
            set.spawn(task.into_future());
        }
        let mut results = vec![];
        while let Some(res) = set.join_next().await {
            results.push(res?);
        }
        Ok(results)
    })
}
