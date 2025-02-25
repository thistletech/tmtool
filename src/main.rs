extern crate i2cdev;
use clap::Parser;

mod args;
mod cmds;
mod trustm;

use anyhow::Result;
use anyhow::*;
use trustm::{TM_SLOT1, TM_SLOT2};

fn main() -> Result<()> {
    let args = args::Args::parse();
    let device = args.device;
    let key_slot =
        u16::from_str_radix(&args.key_slot[2..], 16).context("failed to parse key slot")?;

    if !(key_slot == TM_SLOT1 || key_slot == TM_SLOT2) {
        return Err(anyhow!("key slot must be 0xe0e8 or 0xe0e9"));
    }

    match args.command {
        args::Cmds::Read(p) => cmds::read(device, key_slot, p.raw),
        args::Cmds::Write(p) => cmds::write(device, key_slot, p.key),
        args::Cmds::Lock(p) => cmds::lock(device, key_slot, p.force),
    }
}
