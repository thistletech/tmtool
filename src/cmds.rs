extern crate i2cdev;

use std::io::Write;
use std::path::PathBuf;

use crate::trustm::{self, TM_SLOT1, TM_SLOT2};

use anyhow::Result;
use anyhow::*;

pub fn read(device: String, slot: u16, raw: bool) -> Result<()> {
    let mut tm = trustm::TrustM::init(device)?;

    tm.write_byte(0x84)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let data = [0x81, 0x01, 0x15];
    tm.write_bytes(&data)?;

    tm.write_byte(0x81)?;
    let mut data = [0; 2];
    tm.read_bytes(&mut data)?;

    let data = [
        0x80, 0x03, 0x00, 0x16, 0x08, 0x20, 0xf0, 0x00, 0x00, 0x10, 0xd2, 0x76, 0x00, 0x00, 0x04,
        0x47, 0x65, 0x6e, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6c, 0xbe, 0x40,
    ];
    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;
    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;
    let mut data = [0; 11];
    tm.read_bytes(&mut data)?;

    let data = [0x80, 0x80, 0x00, 0x00, 0x0c, 0xec];
    tm.write_bytes(&data)?;

    let mut data = [
        0x80, 0x04, 0x00, 0x0c, 0x08, 0x20, 0x81, 0x00, 0x00, 0x06, 0xff, 0xff, 0x00, 0x00, 0x06,
        0x11, 0x8b, 0x12,
    ];
    if slot == TM_SLOT1 {
        data[10] = 0xe0;
        data[11] = 0xe8;
        data[16] = 0x8b;
        data[17] = 0x12;
    } else if slot == TM_SLOT2 {
        data[10] = 0xe0;
        data[11] = 0xe9;
        data[16] = 0x80;
        data[17] = 0x56;
    }
    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;
    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;
    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;
    let mut pk = [0; 74];
    tm.read_bytes(&mut pk)?;

    let pk = &pk[9..73];
    eprintln!("~~ Key at slot {:#04x}", slot);
    eprintln!("{:02x?}", pk);

    if raw {
        std::io::stdout().write_all(pk)?;
        std::io::stdout().flush()?;
    }

    Ok(())
}

pub fn write(device: String, slot: u16, keypath: PathBuf) -> Result<()> {
    if !keypath.exists() {
        return Err(anyhow!("key file not found"));
    }

    // Transform PEM to DER using
    let key = std::fs::read(&keypath)?;
    let pem = pem::parse(key).context("invalid key")?;
    let pk = pem.contents();
    if pk.len() < 74 {
        return Err(anyhow!("invalid key length"));
    }
    let pk = &pk[27..];

    eprintln!("~~ Parsed key at {:?}", &keypath);

    let mut tm = trustm::TrustM::init(device)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let data = [0x88, 0x00, 0x00];
    tm.write_bytes(&data)?;

    tm.write_byte(0x84)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let data = [0x81, 0x01, 0x15];
    tm.write_bytes(&data)?;

    tm.write_byte(0x81)?;

    let mut data = [0; 2];
    tm.read_bytes(&mut data)?;

    let data = [
        0x80, 0x03, 0x00, 0x16, 0x08, 0x20, 0xF0, 0x00, 0x00, 0x10, 0xD2, 0x76, 0x00, 0x00, 0x04,
        0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C, 0xBE, 0x40,
    ];
    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 11];
    tm.read_bytes(&mut data)?;

    let data = [0x80, 0x80, 0x00, 0x00, 0x0c, 0xec];
    tm.write_bytes(&data)?;

    let mut beg = [
        0x80, 0x04, 0x00, 0x4A, 0x08, 0x20, 0x82, 0x40, 0x00, 0x44, 0xff, 0xff, 0x00, 0x00,
    ];

    if slot == TM_SLOT1 {
        beg[7] = 0x00;
        beg[10] = 0xe0;
        beg[11] = 0xe8;
    } else if slot == TM_SLOT2 {
        beg[7] = 0x40;
        beg[10] = 0xe0;
        beg[11] = 0xe9;
    }

    let mut end: [u8; 2] = [0x00, 0x00];
    if slot == TM_SLOT1 {
        end = [0x2f, 0x10];
    } else if slot == TM_SLOT2 {
        end = [0x5b, 0xb9];
    }

    let mut data = Vec::new();
    data.extend_from_slice(&beg);
    data.extend_from_slice(pk);
    data.extend_from_slice(&end);

    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 11];
    tm.read_bytes(&mut data)?;

    let data = [0x80, 0x81, 0x00, 0x00, 0x56, 0x30];
    tm.write_bytes(&data)?;

    eprintln!("~~ Key successfuly written to slot {:#04x}", slot);

    Ok(())
}

pub fn lock(device: String, slot: u16, force: bool) -> Result<()> {
    let mut tm = trustm::TrustM::init(device)?;

    if !force {
        // prompt user to make sure they're sure
        eprintln!("Are you sure you want to lock the key? This can only be done once per slot. Type 'yes' to proceed.");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            return Err(anyhow!("user aborted"));
        }
    }

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let data = [0x88, 0x00, 0x00];
    tm.write_bytes(&data)?;

    tm.write_byte(0x84)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let data = [0x81, 0x01, 0x15];
    tm.write_bytes(&data)?;

    tm.write_byte(0x81)?;

    let mut data = [0; 2];
    tm.read_bytes(&mut data)?;

    let data = [
        0x80, 0x03, 0x00, 0x16, 0x08, 0x20, 0xf0, 0x00, 0x00, 0x10, 0xd2, 0x76, 0x00, 0x00, 0x04,
        0x47, 0x65, 0x6e, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6c, 0xbe, 0x40,
    ];
    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 11];
    tm.read_bytes(&mut data)?;

    let data = [0x80, 0x80, 0x00, 0x00, 0x0c, 0xec];
    tm.write_bytes(&data)?;

    let mut data = [
        0x80, 0x04, 0x00, 0x0f, 0x08, 0x20, 0x82, 0x01, 0x00, 0x09, 0xe0, 0xe9, 0x00, 0x00, 0x20,
        0x03, 0xd0, 0x01, 0xff, 0x5d, 0xd8,
    ];
    if slot == TM_SLOT1 {
        data[10] = 0xe0;
        data[11] = 0xe8;
        data[19] = 0xdc;
        data[20] = 0x67;
    } else if slot == TM_SLOT2 {
        data[10] = 0xe0;
        data[11] = 0xe9;
        data[19] = 0x5d;
        data[20] = 0xd8;
    }

    tm.write_bytes(&data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 5];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x82)?;

    let mut data = [0; 4];
    tm.read_bytes(&mut data)?;

    tm.write_byte(0x80)?;

    let mut data = [0; 11];
    tm.read_bytes(&mut data)?;

    let data = [0x80, 0x81, 0x00, 0x00, 0x56, 0x30];
    tm.write_bytes(&data)?;

    eprintln!("~~ Key at slot {:#04x} is now write-protected", slot);

    Ok(())
}
