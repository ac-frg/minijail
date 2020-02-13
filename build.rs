// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Minijail's build script invoked by cargo.
///
/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
/// building libminijail statically.
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> io::Result<()> {
    // Minijail requires libcap at runtime.
    pkg_config::Config::new().probe("libcap").unwrap();

    // Prefer a system-provided Minijail library.
    if pkg_config::Config::new().probe("libminijail").is_ok() {
        // Stamp out a dummy constants.json.

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        fs::write(out_dir.join("constants.json"), "").unwrap();
        return Ok(());
    }

    let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap();

    let status = Command::new("make")
        .current_dir(&out_dir)
        .env("OUT", &out_dir)
        .env("MODE", if profile == "release" { "opt" } else { "debug" })
        .arg("-C")
        .arg(&current_dir)
        .arg("CC_STATIC_LIBRARY(libminijail.pic.a)")
        .arg("constants.json")
        .status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=minijail.pic");
    Ok(())
}
