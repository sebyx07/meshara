use std::io::Result;

fn main() -> Result<()> {
    // Compile Protocol Buffer definitions
    prost_build::Config::new()
        .out_dir("src/protocol")
        .compile_protos(&["proto/messages.proto"], &["proto/"])?;

    Ok(())
}
