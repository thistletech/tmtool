extern crate i2cdev;
use clap::Parser;

mod args;
pub mod trustm;

use std::io::Write;

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
        args::Cmds::Read(p) => {
            let pk = tmtool::read_key(device, key_slot)?;
            if p.raw {
                std::io::stdout().write_all(&pk)?;
                std::io::stdout().flush()?;
            } else {
                eprintln!("~~ Key at slot {:#04x}", key_slot);
                eprintln!("{:02x?}", pk);
            }
        }
        args::Cmds::Write(p) => {
            tmtool::write_key(device, key_slot, p.key)?;
            eprintln!("~~ Key successfuly written to slot {:#04x}", key_slot);
        }
        args::Cmds::Lock(p) => {
            if !p.force {
                eprintln!("Are you sure you want to lock the key? This can only be done once per slot. Type 'yes' to proceed.");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim() != "yes" {
                    return Err(anyhow!("user aborted"));
                }
            }
            tmtool::lock_keyslot(device, key_slot)?;
            eprintln!("~~ Key at slot {:#04x} is now write-protected", key_slot);
        }
        args::Cmds::Verify(p) => {
            tmtool::p256_verify(device, key_slot, p.signature, p.payload)?;
            eprintln!("~~ Signature verified successfully");
        }
    };

    Ok(())
}
