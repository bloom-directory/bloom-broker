fn main() {
    let corpus = format!(
        "{}|{}|{}|{}|{}|{}",
        bloom_solana::golden::FEE_PAYER,
        bloom_solana::golden::DESTINATION,
        bloom_solana::golden::LAMPORTS,
        bloom_solana::golden::MESSAGE_HEX,
        bloom_solana::golden::MESSAGE_DIGEST_HEX,
        bloom_solana::golden::SIGNATURE_HEX,
    );
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(corpus.as_bytes());
    println!("{}", hex::encode(h.finalize()));
}
