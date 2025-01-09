fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=protocol/core/Tron.proto");
    println!("cargo:rerun-if-changed=protocol/core/Contract.proto");
    println!("cargo:rerun-if-changed=protocol/core/Discover.proto");
    println!("cargo:rerun-if-changed=protocol/api/api.proto");

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // the trait `Deserialize<'_>` is not implemented for `prost_types::Any`
        .field_attribute("Contract.parameter", "#[serde(default, skip_deserializing, skip_serializing)]")
        // .extern_path("./protocol", "::")
        .out_dir("./src")
        .compile_protos(
            &[
                "protocol/core/Tron.proto",
                "protocol/core/Contract.proto",
                "protocol/core/Discover.proto",
                "protocol/api/api.proto",
            ],
            &["protocol", "include"],
        )?;

    //    tonic_build::compile_protos("protocol/api/api.proto").expect("protobuf compile");

    /*
    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .includes(&["protocol", "include"])
        .inputs(&[
            "protocol/core/Tron.proto",
            "protocol/core/Contract.proto",
            "protocol/core/Discover.proto",
        ])
        .cargo_out_dir("src")
        .run_from_script();

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .out_dir("src")
        .includes(&["protocol", "include"])
        .input("protocol/api/api.proto")
        .cargo_out_dir("src")
        .run_from_script();

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .out_dir("src")
        .includes(&["protocol", "include"])
        .input("protocol/api/api.proto")
        .cargo_out_dir("src")
        .run_from_script();
    */

    Ok(())
}
