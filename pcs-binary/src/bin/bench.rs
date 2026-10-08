// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{env,fs,path::PathBuf,process::Command};
fn main(){
    if env::args().skip(1).collect::<Vec<_>>() != ["--v08"] {
        eprintln!("usage: bench --v08"); std::process::exit(2);
    }
    let root=PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let st=Command::new(root.join("scripts/run-v08-final-grid.sh"))
        .arg(&root).env("RUNS",env::var("RUNS").unwrap_or_else(|_|"10".into()))
        .env("RUN_N22","0").status().expect("grid runner");
    if !st.success(){std::process::exit(1)}
    let mut ds=fs::read_dir(root.join("freeze-v0.8")).unwrap()
        .filter_map(Result::ok).map(|e|e.path()).filter(|p|p.is_dir()).collect::<Vec<_>>();
    ds.sort();
    let d=ds.last().unwrap();
    println!("{}",fs::read_to_string(d.join("v08-final-grid.tex")).unwrap());
    println!("RESULT_DIR={}",d.display());
}
