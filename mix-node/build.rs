fn main() -> Result<(), Box<dyn std::error::Error>> {
    let includes = ["proto/"];
    let protos = ["proto/mix-node.proto"];

    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&protos, &includes)?;
    // prevent needing to rebuild if files (or deps) haven't changed
    for proto in protos {
        println!("cargo:rerun-if-changed={}", proto);
    }

    // trigger recompilation when a new migration is added
    println!("cargo:rerun-if-changed=migrations");

    Ok(())
}
