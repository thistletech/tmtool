extern crate i2cdev;

pub mod trustm;
use crate::trustm::*;

use std::path::PathBuf;

use std::io::Read;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::EncodedPoint;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustMLibError {
    #[error("trustm device error")]
    DeviceError {
        #[from]
        source: TrustMDeviceError,
    },
    #[error("key error")]
    KeyError(String),
    #[error("signature error")]
    VerifyError(String),
}

pub fn read_key(device: PathBuf, slot: u16) -> Result<Vec<u8>, TrustMLibError> {
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

pub fn write_key(device: PathBuf, slot: u16, keypath: PathBuf) -> Result<(), TrustMLibError> {
    if !keypath.exists() {
        return Err(TrustMLibError::KeyError(format!(
            "key file does not exist: {}",
            keypath.display()
        )));
    }

    // Transform PEM to DER using
    let key = std::fs::read(&keypath)
        .map_err(|e| TrustMLibError::KeyError(format!("failed to read key file: {}", e)))?;
    let pem = pem::parse(key)
        .map_err(|e| TrustMLibError::KeyError(format!("failed to parse PEM: {}", e)))?;
    let pk = pem.contents();
    if pk.len() < 74 {
        return Err(TrustMLibError::KeyError(format!(
            "key file is too short, expected at least 74 bytes, got {}",
            pk.len()
        )));
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

pub fn lock_keyslot(device: PathBuf, slot: u16) -> Result<(), TrustMLibError> {
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

pub fn p256_verify(
    key: PathBuf,
    slot: Option<u16>,
    signature: PathBuf,
    payload: PathBuf,
) -> Result<(), TrustMLibError> {
    let mut file = std::fs::File::open(payload)
        .map_err(|e| TrustMLibError::VerifyError(format!("failed to open payload file: {}", e)))?;
    let mut toverify = Vec::new();
    file.read_to_end(&mut toverify)
        .map_err(|e| TrustMLibError::VerifyError(format!("failed to read payload file: {}", e)))?;

    // read signature from file - raw bytes
    let mut sig_file = std::fs::File::open(signature).map_err(|e| {
        TrustMLibError::VerifyError(format!("failed to open signature file: {}", e))
    })?;
    let mut sig: Vec<u8> = Vec::new();
    sig_file.read_to_end(&mut sig).map_err(|e| {
        TrustMLibError::VerifyError(format!("failed to read signature file: {}", e))
    })?;

    let pk = match slot {
        Some(s) => read_key(key, s)?,
        None => {
            // read key from file
            let mut pk_file = std::fs::File::open(key).map_err(|e| {
                TrustMLibError::VerifyError(format!("failed to open public from TrustM: {}", e))
            })?;
            let mut pk: Vec<u8> = Vec::new();
            pk_file.read_to_end(&mut pk).map_err(|e| {
                TrustMLibError::VerifyError(format!("failed to read public key file: {}", e))
            })?;
            pk
        }
    };

    // reconstruct key
    let mut encoded_bytes = [0u8; 65];
    encoded_bytes[0] = 0x04; // uncompressed point prefix
    encoded_bytes[1..].copy_from_slice(&pk);
    let encoded_point = EncodedPoint::from_bytes(encoded_bytes)
        .map_err(|e| TrustMLibError::VerifyError(format!("failed to parse public key: {}", e)))?;
    let public_key = p256::PublicKey::from_encoded_point(&encoded_point).unwrap();
    let verifying_key = VerifyingKey::from(public_key);

    // parse signature
    let signature = Signature::from_slice(&sig)
        .map_err(|e| TrustMLibError::VerifyError(format!("failed to parse signature: {}", e)))?;

    // verify signature
    verifying_key.verify(&toverify, &signature).map_err(|e| {
        TrustMLibError::VerifyError(format!("signature verification failed: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        p256_verify(
            PathBuf::from("./test-vectors/pk.raw"),
            None,
            PathBuf::from("./test-vectors/sig"),
            PathBuf::from("./test-vectors/pl"),
        )
        .unwrap();
    }
}
