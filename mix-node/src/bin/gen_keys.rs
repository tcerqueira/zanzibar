use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
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
    let participants = serde_json::to_string_pretty(&participants)?;

    println!("{participants}");
    Ok(())
}
