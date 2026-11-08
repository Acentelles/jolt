use std::env;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=JOLT_PREVALIDATED_CATALOG_RS");
    let source = match env::var_os("JOLT_PREVALIDATED_CATALOG_RS") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            fs::read_to_string(path)?
        }
        None => String::from(
            "pub(super) fn rebuild(_family: super::OneHotFamily, _view: &[u8]) -> Option<super::AkitaOneHotBackendScheme> {\nlet _ = super::rebuild_one::<cfg_of!(K16)>;\nNone\n}\n",
        ),
    };
    let output = PathBuf::from(
        env::var_os("OUT_DIR")
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "Cargo did not set OUT_DIR"))?,
    );
    fs::write(output.join("prevalidated_catalog.rs"), source)?;
    Ok(())
}
