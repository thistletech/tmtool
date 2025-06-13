extern crate i2cdev;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use crate::i2cdev::core::I2CDevice;
use i2cdev::linux::*;

use thiserror::Error;

pub const TM_ADDR: u16 = 0x30;

pub const TM_SLOT1: u16 = 0xe0e8;
pub const TM_SLOT2: u16 = 0xe0e9;

pub struct TrustM {
    dev: LinuxI2CDevice,
}

#[derive(Error, Debug)]
pub enum TrustMDeviceError {
    #[error("can not init")]
    CantInit(&'static str),
    #[error("can not init device")]
    CantInitDevice {
        #[from]
        source: i2cdev::linux::LinuxI2CError,
    },
    #[error("can not write to device")]
    WriteError,
    #[error("can not read from device")]
    ReadEror,
}

impl TrustM {
    pub fn init(device: PathBuf) -> Result<TrustM, TrustMDeviceError> {
        let dev = LinuxI2CDevice::new(device, TM_ADDR)
            .map_err(|e| TrustMDeviceError::CantInitDevice { source: e })?;

        let mut tm = TrustM { dev };

        sleep(Duration::from_micros(100 * 1000));

        let data: [u8; 3] = [0x88, 0xff, 0xff]; // reset
        tm.write_bytes(&data)
            .map_err(|_e| TrustMDeviceError::CantInit("can not reset device after init"))?;

        sleep(Duration::from_micros(100 * 1000));
        Ok(tm)
    }

    pub fn write_byte(&mut self, b: u8) -> Result<(), TrustMDeviceError> {
        let mut ret;
        for _ in 0..200 {
            ret = self.dev.smbus_write_byte(b);
            if ret.is_ok() {
                sleep(Duration::from_micros(10 * 1000)); // delay & return
                return Ok(());
            }
            sleep(Duration::from_micros(1000)); // delay & retry
        }
        Err(TrustMDeviceError::WriteError)
    }

    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), TrustMDeviceError> {
        let mut ret;
        for _ in 0..200 {
            ret = self.dev.write(b);
            if ret.is_ok() {
                sleep(Duration::from_micros(10 * 1000)); // delay & return
                return Ok(());
            }
            sleep(Duration::from_micros(1000)); // delay & retry
        }
        Err(TrustMDeviceError::WriteError)
    }

    pub fn read_bytes(&mut self, b: &mut [u8]) -> Result<(), TrustMDeviceError> {
        let mut ret;
        for _ in 0..200 {
            ret = self.dev.read(b);
            if ret.is_ok() {
                sleep(Duration::from_micros(500)); // delay & return
                return Ok(());
            }
            sleep(Duration::from_micros(1000)); // delay & retry
        }
        Err(TrustMDeviceError::ReadEror)
    }
}
