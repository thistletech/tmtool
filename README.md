# tmtool

Simple tool to read/write keys to Infineon TrustM platforms.

Pre-built binaries for aarch64 available in the [releases section](https://github.com/thistletech/tmtool/releases).

## Usage

```bash
$ ./tmtool --help
TrustM Userland tooling
This tool can read and write keys to the Infineon TrustM chip.
Requires a direct i2c connection to the chip.

Usage: tmtool [OPTIONS] <COMMAND>

Commands:
  read   Read a key from TrustM
  write  Write a key to TrustM
  lock   Write protect a key - warning, you can only do this once per slot !
  help   Print this message or the help of the given subcommand(s)

Options:
      --device <DEVICE>      i2c device path [default: /dev/i2c-1]
      --key-slot <KEY_SLOT>  Trust M key slot to use [default: 0xe0e8]
  -h, --help                 Print help
  -V, --version              Print version
```
