// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wrapper for the Python-based seccomp policy compiler.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string;

use tempfile::TempDir;

/// An action to be taken when a system call violates seccomp policy.
pub enum Action {
    /// Kills the thread or process, depending on if the policy allows `SECCOMP_RET_KILL_PROCESS`.
    Kill,
    /// Kills the process.
    KillProcess,
    /// Kills the thread.
    KillThread,
    /// Sends a SIGSYS signal to the triggering thread.
    Trap,
    /// The kernel will attempt to notify a tracer process, otherwise returns ENOSYS.
    Trace,
    /// The system call is executed but logged.
    Log,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::KillProcess => write!(f, "kill-process"),
            Action::KillThread => write!(f, "kill-thread"),
            Action::Kill => write!(f, "kill"),
            Action::Trap => write!(f, "trap"),
            Action::Trace => write!(f, "trace"),
            Action::Log => write!(f, "log"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Starting the compiler process failed.
    CommandFailed(io::Error),
    /// The compiler failed to build the policy.
    CompileFailed(String, String),
    /// The compiler's stderr could not be parsed.
    ParseStderr(string::FromUtf8Error),
    /// The compiler's stdout could not be parsed.
    ParseStdout(string::FromUtf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CommandFailed(e) => write!(f, "failed to run compiler: {}", e),
            Error::CompileFailed(stdout, stderr) => write!(
                f,
                "compilation failed: stdout: {}, stderr: {}",
                stdout, stderr
            ),
            Error::ParseStderr(e) => write!(f, "failed to parse stderr: {}", e),
            Error::ParseStdout(e) => write!(f, "failed to parse stdout: {}", e),
        }
    }
}

/// A seccomp policy to be compiled.
pub struct Policy<'a> {
    /// The path to the input policy file.
    policy_path: &'a Path,
    /// The path where the compiled BPF file will be placed.
    output_path: &'a Path,
    /// Indicates if SECCOMP_RET_KILL_PROCESS is supported as the default kill action. Don't use
    /// on kernels prior to 4.14.
    kill_process: bool,
    /// The default action for a seccomp violation, overriding any default in the policy file.
    default_action: Option<Action>,
}

/// The seccomp policy compiler.
pub struct PolicyCompiler {
    compiler_path: PathBuf,
    constants_path: PathBuf,
    _tempdir: TempDir,
}

impl PolicyCompiler {
    /// Creates the environment necessary to run the policy compiler.
    pub fn new() -> io::Result<PolicyCompiler> {
        const CONSTANTS: &str = include_str!(concat!(env!("OUT_DIR"), "/constants.json"));
        const COMPILE_SECCOMP_POLICY: &str = include_str!("tools/compile_seccomp_policy.py");
        const ARCH: &str = include_str!("tools/arch.py");
        const BPF: &str = include_str!("tools/bpf.py");
        const COMPILER: &str = include_str!("tools/compiler.py");
        const PARSER: &str = include_str!("tools/parser.py");

        const COMPILER_MAIN: &str = "compile_seccomp_policy.py";

        struct CompilerFile<'a> {
            name: &'a str,
            contents: &'a str,
        }

        let files = &[
            CompilerFile::<'static> {
                name: "constants.json",
                contents: CONSTANTS,
            },
            CompilerFile::<'static> {
                name: COMPILER_MAIN,
                contents: COMPILE_SECCOMP_POLICY,
            },
            CompilerFile::<'static> {
                name: "arch.py",
                contents: ARCH,
            },
            CompilerFile::<'static> {
                name: "bpf.py",
                contents: BPF,
            },
            CompilerFile::<'static> {
                name: "compiler.py",
                contents: COMPILER,
            },
            CompilerFile::<'static> {
                name: "parser.py",
                contents: PARSER,
            },
        ];

        let tempdir = TempDir::new()?;
        let dir = tempdir.path();
        for file in files.iter() {
            fs::write(dir.join(file.name), file.contents)?;
        }

        // Make the compiler executable.
        let compiler_main_path = dir.join(COMPILER_MAIN);
        let metadata = fs::metadata(&compiler_main_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&compiler_main_path, perms)?;

        Ok(PolicyCompiler {
            compiler_path: compiler_main_path,
            constants_path: dir.join("constants.json"),
            _tempdir: tempdir,
        })
    }

    /// Overrides the built-in constants.json with a user-provided one. Useful for
    /// cross-compilation.
    pub fn arch_constants(&mut self, path: &Path) -> &mut Self {
        self.constants_path = PathBuf::from(path);

        self
    }

    /// Compiles the supplied policy file.
    pub fn compile(&self, policy: &Policy) -> Result<(), Error> {
        let mut command = Command::new(&self.compiler_path);

        if policy.kill_process {
            command.arg("--use-kill-process");
        }

        if let Some(ref action) = policy.default_action {
            command.arg("--default-action").arg(action.to_string());
        }

        command.arg(policy.policy_path).arg(policy.output_path);

        let output = command.output().map_err(Error::CommandFailed)?;
        if !output.status.success() {
            let stdout = String::from_utf8(output.stdout).map_err(Error::ParseStdout)?;
            let stderr = String::from_utf8(output.stderr).map_err(Error::ParseStderr)?;
            return Err(Error::CompileFailed(stdout, stderr));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_cat_example() {
        let compiler = PolicyCompiler::new().unwrap();
        let tempdir = TempDir::new().unwrap();

        compiler
            .compile(&Policy {
                policy_path: Path::new("examples/cat.policy"),
                output_path: &tempdir.path().join("foo"),
                kill_process: true,
                default_action: Some(Action::Kill),
            })
            .expect("failed to build example policy");
    }

    #[test]
    fn compile_fails() {
        let compiler = PolicyCompiler::new().unwrap();
        let tempdir = TempDir::new().unwrap();

        compiler
            .compile(&Policy {
                policy_path: Path::new("examples/doesntexist.policy"),
                output_path: &tempdir.path().join("foo"),
                kill_process: true,
                default_action: Some(Action::Kill),
            })
            .expect_err("didn't fail to compile nonexistent policy");
    }
}
