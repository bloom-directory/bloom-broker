fn main() {
    let corpus = format!(
        "{}|{}|{}|{}|{}|{}",
        bloom_solana_verify::golden::FEE_PAYER,
        bloom_solana_verify::golden::DESTINATION,
        bloom_solana_verify::golden::LAMPORTS,
        bloom_solana_verify::golden::MESSAGE_HEX,
        bloom_solana_verify::golden::MESSAGE_DIGEST_HEX,
        bloom_solana_verify::golden::SIGNATURE_HEX,
    );
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(corpus.as_bytes());
    println!("{}", hex::encode(h.finalize()));
}
