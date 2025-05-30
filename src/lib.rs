extern crate i2cdev;

pub mod trustm;
use crate::trustm::*;

use std::path::PathBuf;

use std::io::Read;

use anyhow::Result;
use anyhow::*;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::EncodedPoint;

pub fn read_key(device: PathBuf, slot: u16) -> Result<Vec<u8>> {
    let mut tm = TrustM::init(device)?;

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
    Ok(pk.to_vec())
}

pub fn p256_verify(
    device: PathBuf,
    slot: u16,
    signature: PathBuf,
    payload: PathBuf,
) -> Result<()> {
    let mut file = std::fs::File::open(payload).context("cant open file to verify")?;
    let mut toverify = Vec::new();
    file.read_to_end(&mut toverify)?;

    // read signature from file - raw bytes
    let mut sig_file = std::fs::File::open(signature).context("cant open signature")?;
    let mut sig: Vec<u8> = Vec::new();
    sig_file.read_to_end(&mut sig)?;

    // if device starts by /dev read from trustm, otherwise read from file
    let pk = if device.starts_with("/dev") {
        read_key(device, slot)?
    } else {
        let mut pk_file = std::fs::File::open(device).context("cant open public key")?;
        let mut pk: Vec<u8> = Vec::new();
        pk_file.read_to_end(&mut pk)?;
        pk
    };

    // reconstruct key
    let mut encoded_bytes = [0u8; 65];
    encoded_bytes[0] = 0x04; // uncompressed point prefix
    encoded_bytes[1..].copy_from_slice(&pk);
    let encoded_point = EncodedPoint::from_bytes(encoded_bytes).context("invalid key")?;
    let public_key = p256::PublicKey::from_encoded_point(&encoded_point).unwrap();
    let verifying_key = VerifyingKey::from(public_key);

    let signature = Signature::from_slice(&sig).context("invalid signature")?;
    verifying_key
        .verify(&toverify, &signature)
        .context("signature cannot be verified")?;

    Ok(())
}

pub fn write_key(device: PathBuf, slot: u16, keypath: PathBuf) -> Result<()> {
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

    let mut tm = TrustM::init(device)?;

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

    Ok(())
}

pub fn lock_keyslot(device: PathBuf, slot: u16) -> Result<()> {
    let mut tm = TrustM::init(device)?;

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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        let slot = TM_SLOT1;
        p256_verify(PathBuf::from("./test-vectors/pk.raw"), slot, PathBuf::from("./test-vectors/sig"), PathBuf::from("./test-vectors/pl")).unwrap();
    }
}
