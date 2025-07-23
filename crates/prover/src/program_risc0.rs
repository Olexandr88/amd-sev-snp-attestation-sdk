use std::marker::PhantomData;

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolValue;
use anyhow::anyhow;
use bonsai_sdk::blocking::Client;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, VERSION};

use crate::{
    program::{Program, RemoteProverConfig},
    RawProof, RawProofType,
};

#[derive(Debug, Clone)]
pub struct RiscZeroProverConfig {
    pub api_url: Option<String>,
    pub api_key: Option<String>,
}

impl Default for RiscZeroProverConfig {
    fn default() -> Self {
        RiscZeroProverConfig {
            api_url: std::env::var("BONSAI_API_URL").ok(),
            api_key: std::env::var("BONSAI_API_KEY").ok(),
        }
    }
}

impl TryFrom<RiscZeroProverConfig> for RemoteProverConfig {
    type Error = anyhow::Error;
    fn try_from(value: RiscZeroProverConfig) -> anyhow::Result<Self> {
        Ok(RemoteProverConfig {
            api_url: value.api_url.ok_or_else(|| anyhow!("missing BONSAI_API_URL"))?,
            api_key: value.api_key.ok_or_else(|| anyhow!("missing BONSAI_API_KEY"))?,
        })
    }
}

#[derive(Clone)]
pub struct ProgramRisc0<ZkType, Input, Output> {
    zktype: ZkType,
    elf: &'static [u8],
    image_id: [u32; 8],
    _marker: PhantomData<(Input, Output)>,
}

impl<ZkType, Input, Output> ProgramRisc0<ZkType, Input, Output> {
    pub fn new(zktype: ZkType, elf: &'static [u8], image_id: [u32; 8]) -> Self {
        ProgramRisc0 {
            zktype,
            elf,
            image_id,
            _marker: PhantomData,
        }
    }

    pub fn gen_raw_proof(&self, env: ExecutorEnv, opts: &ProverOpts) -> anyhow::Result<RawProof> {
        let prover = default_prover();
        let prove_info = prover.prove_with_opts(env, self.elf, opts)?;
        let journal: Bytes = prove_info.receipt.journal.bytes.clone().into();
        let claim = prove_info.receipt.inner;
        let proof = RawProof::from_proof(&claim, journal)?;
        Ok(proof)
    }
}

impl<ZkType, Input, Output> Program for ProgramRisc0<ZkType, Input, Output>
where
    Input: SolValue + Send + Sync,
    Output: SolValue + Send + Sync,
    ZkType: Send + Sync + Copy,
{
    type Input = Input;
    type Output = Output;
    type ZkType = ZkType;
    fn version(&self) -> &'static str {
        VERSION
    }
    fn zktype(&self) -> Self::ZkType {
        self.zktype
    }

    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        let receipt = proof.decode_proof::<InnerReceipt>()?;
        let encoded_proof = match receipt {
            InnerReceipt::Groth16(groth16_receipt) => groth16::encode(&groth16_receipt.seal)?,
            _ => vec![],
        };
        Ok(encoded_proof.into())
    }

    fn upload_image(&self, cfg: &RemoteProverConfig) -> anyhow::Result<()> {
        let client = Client::from_parts(cfg.api_url.clone(), cfg.api_key.clone(), VERSION)?;
        let image_id = Digest::new(self.image_id);
        println!("image_id: {:?}", image_id.to_string());
        client.upload_img(&image_id.to_string(), self.elf.to_vec())?;
        Ok(())
    }

    fn program_id(&self) -> B256 {
        B256::from_slice(Digest::new(self.image_id).as_bytes())
    }

    fn verify_proof_id(&self) -> B256 {
        self.program_id()
    }

    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_composite_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof> {
        let mut env = ExecutorEnv::builder();
        if let Some(encoded_composite_proofs) = encoded_composite_proofs {
            for proof in encoded_composite_proofs {
                let item = bincode::deserialize::<InnerReceipt>(proof)?;
                env.add_assumption(item);
            }
        }
        let env = env.write_slice(&input.abi_encode()).build()?;
        let opts = match raw_proof_type {
            RawProofType::Groth16 => ProverOpts::groth16(),
            RawProofType::Composite => ProverOpts::composite(),
        };
        Ok(self.gen_raw_proof(env, &opts)?)
    }
}
