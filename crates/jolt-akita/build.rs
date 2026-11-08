use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=JOLT_PREVALIDATED_CATALOG_RS");
    let source = match env::var_os("JOLT_PREVALIDATED_CATALOG_RS") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            fs::read_to_string(path).expect("read trusted prevalidated catalog dispatch")
        }
        None => String::from(
            "pub(super) fn rebuild(_family: super::OneHotFamily, _view: &[u8]) -> Option<super::AkitaOneHotBackendScheme> {\nlet _ = super::rebuild_one::<cfg_of!(K16)>;\nNone\n}\n",
        ),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(output.join("prevalidated_catalog.rs"), source)
        .expect("write trusted prevalidated catalog dispatch");
}
