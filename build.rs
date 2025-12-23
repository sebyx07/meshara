use std::io::Result;

fn main() -> Result<()> {
    // Compile Protocol Buffer definitions
    let mut config = prost_build::Config::new();
    config.out_dir("src/protocol");

    // Format the generated code to match project style
    config.format(true);

    config.compile_protos(&["proto/messages.proto"], &["proto/"])?;

    Ok(())
}
