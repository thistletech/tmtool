use std::path::PathBuf;

use clap::{Parser, Subcommand};

// CLI Interface
#[derive(Parser)]
#[command(
    name = "TrustM Userland Driver",
    author = "Thistle Tech <pierre@thistle.tech>",
    arg_required_else_help = true,
    version = option_env!("TM_TOOL").unwrap_or("unknown"),
    long_about = None,
    about = "
TrustM Userland tooling.
Designed to help integration with Thistle Verified Boot: https://docs.thistle.tech/tvb

This tool can read and write keys to the Infineon TrustM chip.
Requires a direct i2c connection to the chip.

Currently limited to reading 64B keys at slots 0xe0e8 and 0xe0e9.
The key writing operation expects a PEM formatted key file.",
    verbatim_doc_comment,
)]
pub struct Args {
    /// i2c device path
    #[clap(long, default_value = "/dev/i2c-1")]
    pub device: String,

    /// Trust M key slot to use
    #[clap(long, default_value = "0xe0e8")]
    pub key_slot: String,

    #[clap(subcommand)]
    pub command: Cmds,
}

#[derive(Subcommand)]
#[clap(arg_required_else_help = true)]
pub enum Cmds {
    #[clap(display_order = 1)]
    /// Read a key from TrustM
    Read(ReadCmd),

    #[clap(display_order = 2)]
    /// Write a key to TrustM
    Write(WriteCmd),

    #[clap(display_order = 3)]
    /// Write protect a key - warning, you can only do this once per slot !
    Lock(LockCmd),
}

#[derive(clap::Args)]
pub struct ReadCmd {}

#[derive(clap::Args)]
pub struct WriteCmd {
    /// Key path. Expects PEM format.
    #[clap(long)]
    pub key: PathBuf,
}

#[derive(clap::Args)]
pub struct LockCmd {
    /// Do not prompt for confirmation
    #[clap(long, short, default_value = "false")]
    pub force: bool,
}
