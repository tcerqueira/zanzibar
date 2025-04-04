# Zanzibar

Distributed cryptographic protocol.

## Overview

## Run

To run the tests:
```bash
cargo test
```

To run the benchmarks:
```bash
cargo bench
```

To generate documentation:
```bash
cargo doc --open
```

## Demo

To run a demo we need:
- A shared key
- 3 mix nodes
- 1 client

There's a key already configured in `mix-node/config/crypto.json`. However, the `secret_key` will be different for each node, this will be overriden with environment variables later.

### Keys
- Participant 0: `secret_key = "D7W4K_1QPjuoEQNsTeyWT92yHSPp67-sApmGksw9EQo"`
- Participant 1: `secret_key = "XGaup1prWoijF91au13Qv2OgqGjo-uE74szhzGbXUgw"`
- Participant 2: `secret_key = "qRekI7iFdtWeHbdJKc8JMOqNM67nCQTLwQA9BwFxlA4"`

<!-- If you want to generate keys yourself, you can run:
```bash
# 3 participants with 2 minimum threshold
cargo run --bin gen_keys -- 2 3
```
And then copy the `key_set` into the `crypto.json` config file. -->

<details>
<summary>If you want to generate keys yourself (optional)</summary>

To generate a new set of keys:
```bash
# 3 participants with 2 minimum threshold
cargo run --bin gen_keys -- 2 3
```
Copy the resulting `key_set` into the `crypto.json` config file.
</details>

### Running Mix Nodes

We can spin up the 3 mix nodes like so:
```bash
# For more detailed logs, run these before starting the servers:
# export RUST_LOG=info,mix_node=trace,tower_http=debug

# Participant 0
APP_CRYPTO__SECRET_KEY="D7W4K_1QPjuoEQNsTeyWT92yHSPp67-sApmGksw9EQo" \
APP_CRYPTO__WHOAMI="0" \
APP_APPLICATION__PORT="6000" \
cargo run --bin rest --release

# Participant 1
APP_CRYPTO__SECRET_KEY="XGaup1prWoijF91au13Qv2OgqGjo-uE74szhzGbXUgw" \
APP_CRYPTO__WHOAMI="1" \
APP_APPLICATION__PORT="6001" \
cargo run --bin rest --release

# Participant 2
APP_CRYPTO__SECRET_KEY="qRekI7iFdtWeHbdJKc8JMOqNM67nCQTLwQA9BwFxlA4" \
APP_CRYPTO__WHOAMI="2" \
APP_APPLICATION__PORT="6002" \
cargo run --bin rest --release
```

### Running the Client

Now that the network of mix-nodes is up and running, we can run the client that will request a comparison:
```bash
# two codes of length 10
cargo run --example demo -- 10

# two codes of length 12800
cargo run --example demo -- 12800
```
**Note:** Because the servers are running on the same machine and the operations are very CPU heavy, the performance is not truly representative of a real-world deployment.

### How it Works

The client:
1. Requests the public key to encrypt the codes (instead of hardcoding it)
2. Generates a random code with the given length and clones it (both codes will be identical)
3. Encrypts both codes and sends a request to "http://localhost:6000/hamming"
4. Since the codes are identical, the expected hamming distance is 0

### Testing Threshold Decryption

To test threshold decryption:
1. Shutdown the mix-node on port `6002` and run the client again - it should still compute the hamming distance
2. Shutdown another mix-node (port `6001`) - the network can no longer compute the hamming distance because the number of nodes is below the threshold, returning an error

The code for the client can be found at `mix-node/examples/demo`.
