use std::io::Result;
use std::process::Command;

fn main() -> Result<()> {
    // Compile Protocol Buffer definitions
    let mut config = prost_build::Config::new();
    config.out_dir("src/protocol");

    config.compile_protos(&["proto/messages.proto"], &["proto/"])?;

    // Format the generated code to ensure consistent formatting
    // This is needed because prost's built-in formatter doesn't always match rustfmt
    let _ = Command::new("rustfmt")
        .arg("src/protocol/meshara.rs")
        .status();

    Ok(())
}
