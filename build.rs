// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

// Minijail generates tables with constants and system calls available for the target architecture.
// This is a two-step process. The compiler first runs a preprocessor-only pass that #includes
// syscalls and constants, then a shell script massages the output of the preprocessor into a .c
// file that holds the table of names to constant/syscall values.
fn generate_constants(const_type: &'static str) -> PathBuf {
    let out_dir = env::var("OUT_DIR").unwrap();

    let input_filename = format!("gen_{}.c", const_type);
    let preprocessed_filename = format!("lib{}.gen.c", const_type);
    let generated_filename = format!("lib{}.c", const_type);
    let generator_script = format!("./gen_{}.sh", const_type);

    let preprocessed_content = cc::Build::new()
        .file(input_filename)
        .flag("-dD")
        .flag("-Werror")
        .expand();
    let preprocessed_path = Path::new(&out_dir).join(preprocessed_filename);
    {
        let mut f = File::create(&preprocessed_path).unwrap();
        f.write_all(&preprocessed_content).unwrap();
    }

    let generated_path = Path::new(&out_dir).join(generated_filename);
    Command::new(generator_script)
        .args(&[preprocessed_path.as_os_str(), generated_path.as_os_str()])
        .status()
        .unwrap();

    generated_path.to_path_buf()
}

fn main() -> io::Result<()> {
    // minijail requires libcap at runtime.
    pkg_config::Config::new().probe("libcap").unwrap();

    // Prefer a system-provided minijail library.
    if pkg_config::Config::new().probe("libminijail").is_ok() {
        return Ok(());
    }

    let constants_c_path = generate_constants("constants");
    let syscalls_c_path = generate_constants("syscalls");

    cc::Build::new()
        .file(constants_c_path.as_os_str())
        .file(syscalls_c_path.as_os_str())
        .file("bpf.c")
        .file("libminijail.c")
        .file("signal_handler.c")
        .file("syscall_filter.c")
        .file("syscall_wrapper.c")
        .file("system.c")
        .file("util.c")
        .include(".")
        .define("PRELOADPATH", r#""invalid""#)
        .compile("libminijail");

    Ok(())
}
