//! `archangel` — friendly launcher and meta-package entry point.
//!
//! Installing the `archangel` package pulls the whole system (daemon,
//! executor, operator CLI). This thin binary simply forwards every
//! argument to `archangelctl`, so `archangel setup`, `archangel session`,
//! `archangel doctor`, `archangel audit-tail …` all work as expected. It
//! holds no logic and no privilege of its own — every security decision
//! still happens in the tools it delegates to.

#![forbid(unsafe_code)]
#![allow(clippy::print_stderr)]

use std::os::unix::process::CommandExt as _;

fn main() -> std::process::ExitCode {
    // Replace this process image with archangelctl, preserving args.
    // `exec` only returns on failure (e.g. archangelctl not on PATH).
    let err = std::process::Command::new("archangelctl")
        .args(std::env::args_os().skip(1))
        .exec();

    eprintln!(
        "archangel: could not launch `archangelctl` ({err}). Is the \
         archangelctl package installed and on PATH?"
    );
    std::process::ExitCode::from(127)
}
