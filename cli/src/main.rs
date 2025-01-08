// Copyright 2024 Irreducible Inc.

use clap::clap_app;

fn main() -> anyhow::Result<()> {
    let matches = clap_app!(binius_mpt_verifier_cli =>
        (version: "0.1.0")
        (author: "Irreducible Team <hello@irreducible.com>")
        (about: "Download MPT proofs from an HTTP provider and verify them")
        (@arg block: -b --block +takes_value "Block hash of the block you want to fetch and verify the proof from")
        (@arg provider: -p --provider +takes_value default_value("https://d1fewb1usrx1oo.cloudfront.net") "The http proof provider you want to download proofs from")
        (@arg tracing: -t --tracing "Show detailed performance information for verify")
    ).get_matches();

    let tracing = matches.is_present("tracing");
    let Some(block) = matches.value_of("block") else {
        anyhow::bail!("You must specify a bloch hash using the --block flag");
    };
    let provider = matches.value_of("provider").expect("has a default value");
    let url = format!("{provider}/block-proof-{block}");

    let t0 = std::time::Instant::now();
    println!("Downloading proof...");
    let proof_bytes = tokio::runtime::Runtime::new()?.block_on(download_from_url(url))?;
    println!(
        "Downloaded proof with {} bytes in {:?}",
        proof_bytes.len(),
        t0.elapsed()
    );
    println!(
        "Proof version = {}",
        u16::from_le_bytes(proof_bytes[6..8].try_into().unwrap())
    );

    let _guard =
        tracing.then(|| tracing_profile::init_tracing().expect("failed to initialize tracing"));
    binius_mp3::verify(proof_bytes)?;

    println!("Successfully verified proof");

    Ok(())
}

async fn download_from_url(url: String) -> Result<Vec<u8>, reqwest::Error> {
    let client = reqwest::Client::new();

    let response = client.get(url).send().await?;
    let response = response.error_for_status()?;

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}
