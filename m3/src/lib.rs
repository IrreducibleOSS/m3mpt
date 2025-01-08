// Copyright 2024 Irreducible Inc.

use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
    constraint_system::channel::{Boundary, ChannelId, FlushDirection},
    constraint_system::Proof,
    fiat_shamir::HasherChallenger,
    oracle::ConstraintSet,
    oracle::OracleId,
    tower::CanonicalTowerFamily,
};
use binius_field::{
    arch::OptimalUnderlier,
    as_packed_field::{PackScalar, PackedType},
    underlier::{UnderlierType, WithUnderlier},
    BinaryField, BinaryField128b, BinaryField16b, BinaryField1b, BinaryField32b, BinaryField64b,
    BinaryField8b, ExtensionField, Field, PackedField, TowerField,
};
use binius_hal::ComputationBackend;
use binius_math::{ArithExpr, IsomorphicEvaluationDomainFactory};
type U = OptimalUnderlier;

use bytemuck::Pod;
use itertools::izip;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;

pub(crate) use crate::utils::macros::{
    populate_committed_polys, populate_committed_polys_with_default,
};
use alloy::{
    primitives::Address,
    primitives::{keccak256, Bytes},
    rlp::Decodable,
    rpc::types::EIP1186AccountProofResponse,
};
use anyhow::anyhow;
use binius_hash::compress::Groestl256ByteCompression;

#[derive(Debug)]
pub struct AccountProof {
    pub address: Address,
    pub nodes: Vec<Vec<u8>>,
}

type B1 = BinaryField1b;
type B8 = BinaryField8b;
type _B16 = BinaryField16b;
type B32 = BinaryField32b;
type B64 = BinaryField64b;
type B128 = BinaryField128b;

mod mpt;
mod tables;
mod utils;

use mpt::*;
use tables::*;
use utils::*;

pub use mpt::TableType;
pub use tracing::instrument;

const LOG_INVERSE_RATE: usize = 2;
const SECURITY_BITS: usize = 100;

pub fn prove(
    alloy_account_proofs: Vec<EIP1186AccountProofResponse>,
    backend: &impl ComputationBackend,
) -> Result<(Vec<u8>, MPTProofInfo), anyhow::Error> {
    let _scope = tracing::debug_span!("binius_mp3::prove", n_accounts = alloy_account_proofs.len())
        .entered();

    let (statement, account_proofs) = get_statement_and_account_proofs(alloy_account_proofs);
    let mut mpt = MPT::new(statement);

    let advice = mpt.process_account_proofs(account_proofs);

    let allocator = bumpalo::Bump::new();
    let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

    let (_boundaries, statement) = mpt.build(&mut builder, advice.clone())?;

    let witness = builder.take_witness()?;
    let constraint_system = builder.build()?;

    // println!("validating");
    // use binius_core::constraint_system::validate::validate_witness;
    // validate_witness(&constraint_system, &_boundaries, &witness).unwrap();

    let domain_factory = IsomorphicEvaluationDomainFactory::<B8>::default();
    let proof = binius_core::constraint_system::prove::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        _,
        groestl_crypto::Groestl256,
        Groestl256ByteCompression,
        HasherChallenger<groestl_crypto::Groestl256>,
        _,
    >(
        &constraint_system,
        LOG_INVERSE_RATE,
        SECURITY_BITS,
        witness,
        &domain_factory,
        &backend,
    )?;

    let info = MPTProofInfo {
        transcript_len: proof.transcript.len(),
        advice_len: proof.advice.len(),
        table_heights: advice.table_heights.as_list(),
    };

    let serialized_proof = MPTProof {
        proof_transcript: proof.transcript,
        proof_advice: proof.advice,
        advice,
        statement,
    }
    .to_bytes()?;
    verify(serialized_proof.clone())?;

    Ok((serialized_proof, info))
}

#[instrument("binius_mp3::verify", skip_all, level = "debug")]
pub fn verify(proof: Vec<u8>) -> Result<(), anyhow::Error> {
    tracing::info!("Proof size: {} bytes", proof.len());

    let proof = MPTProof::from_bytes(proof)?;
    let mpt = MPT::new(proof.statement);

    let mut builder = ConstraintSystemBuilder::new();

    let (boundaries, _statement) = mpt.build(&mut builder, proof.advice)?;

    let constraint_system = builder.build()?;

    binius_core::constraint_system::verify::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        groestl_crypto::Groestl256,
        Groestl256ByteCompression,
        HasherChallenger<groestl_crypto::Groestl256>,
    >(
        &constraint_system,
        LOG_INVERSE_RATE,
        SECURITY_BITS,
        boundaries,
        Proof {
            transcript: proof.proof_transcript,
            advice: proof.proof_advice,
        },
    )?;

    Ok(())
}

#[derive(Serialize, Debug, Deserialize)]
struct MPTProof {
    proof_transcript: Vec<u8>,
    proof_advice: Vec<u8>,
    advice: Advice,
    statement: Statement,
}

impl MPTProof {
    const MPT_PROOF_VERSION: u16 = 3;
    const MAGIC_NUMBER: [u8; 6] = *b"BINIUS";

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, anyhow::Error> {
        if data.len() < 8 {
            return Err(anyhow!("Byte array is too short."));
        }

        let magic_number = &data[0..6];
        if magic_number != Self::MAGIC_NUMBER {
            return Err(anyhow!(
                "The data does not seem to be a binius proof {:?}. Expected proof to start with {:?}",
                magic_number,
                Self::MAGIC_NUMBER
            ));
        }
        let version = u16::from_le_bytes([data[6], data[7]]);

        if version != Self::MPT_PROOF_VERSION {
            return Err(anyhow!(
                "Proof version {version} not supported by this verifier. Supported version = {}",
                Self::MPT_PROOF_VERSION
            ));
        }

        let proof_data = &data[8..];
        let deserialized_struct: Self = bincode::deserialize(proof_data)?;

        Ok(deserialized_struct)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut result = Vec::new();

        result.write_all(&Self::MAGIC_NUMBER)?;
        result.write_all(&Self::MPT_PROOF_VERSION.to_le_bytes())?;
        let serialized_proof = bincode::serialize(&self)?;

        result.extend(serialized_proof);
        Ok(result)
    }
}

pub fn get_zerocheck_constraints() -> Result<Vec<ZerocheckSet<B128>>, anyhow::Error> {
    let mut mpt = MPT::new(Statement::default());
    let advice = mpt.process_account_proofs(vec![]);
    let allocator = bumpalo::Bump::new();
    let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);
    let _ = mpt.build(&mut builder, advice)?;
    let constraint_system = builder.build()?;
    Ok(constraint_system
        .table_constraints
        .into_iter()
        .map(
            |ConstraintSet {
                 oracle_ids,
                 constraints,
                 n_vars,
             }| {
                ZerocheckSet {
                    n_vars,
                    oracle_ids,
                    arith_exprs: constraints.into_iter().map(|c| c.composition).collect(),
                }
            },
        )
        .collect())
}

pub struct ZerocheckSet<F: Field> {
    pub n_vars: usize,
    pub oracle_ids: Vec<OracleId>,
    pub arith_exprs: Vec<ArithExpr<F>>,
}

/// Proof metadata
pub struct MPTProofInfo {
    /// Proof transcript size
    pub transcript_len: usize,
    /// Proof advice size
    pub advice_len: usize,
    /// Metadata related to tables
    pub table_heights: HashMap<TableType, (usize, usize)>,
}
