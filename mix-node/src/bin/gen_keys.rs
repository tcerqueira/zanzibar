use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
    CandidateDecryption,
};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let _ignore_bin = args.next();
    let threshold = args
        .next()
        .expect("missing threshold value: e.g. gen_keys 2 3")
        .parse()?;
    let shares = args
        .next()
        .expect("missing shares value: e.g. gen_keys 2 3")
        .parse()?;
    let params = Params::new(shares, threshold);

    // Initialize the dealer.
    let mut rng = rand::thread_rng();
    let dealer = Dealer::<Ristretto>::new(params, &mut rng);
    let (public_poly, poly_proof) = dealer.public_info();
    let key_set = PublicKeySet::new(params, public_poly, poly_proof)?;

    // Initialize participants based on secret shares provided by the dealer.
    let participants = (0..shares)
        .map(|i| ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i)))
        .collect::<Result<Vec<_>, _>>()?;
    let participants_json = serde_json::to_string_pretty(&participants)?;

    println!("{participants_json}");

    // At last, participants can decrypt messages!
    let encrypted_value = 5_u64;
    let enc = key_set.shared_key().encrypt(encrypted_value, &mut rng);
    let shares_with_proofs: Vec<_> = participants
        .iter()
        .map(|p| p.decrypt_share(enc, &mut rng))
        .take(2)
        .collect(); // emulate the 3rd participant dropping off

    // Emulate share transfer via untrusted network.
    let _dec_shares: Vec<_> = shares_with_proofs
        .iter()
        .enumerate()
        .map(|(i, (share, proof))| {
            let share = CandidateDecryption::from_bytes(&share.to_bytes()).unwrap();
            key_set.verify_share(share, enc, i, proof).unwrap()
        })
        .collect();

    Ok(())
}
