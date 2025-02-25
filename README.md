# tmtool

Simple tool to read/write keys to Infineon TrustM platforms.

Pre-built binaries for aarch64 available in the [releases section](https://github.com/thistletech/tmtool/releases).

## Usage

```txt
TrustM Userland tooling.
Designed to help integration with Thistle Verified Boot: https://docs.thistle.tech/tvb

This tool can read and write keys to the Infineon TrustM chip.
Requires a direct i2c connection to the chip.

Currently limited to 64B keys at slots 0xe0e8 and 0xe0e9.
The key writing operation expects a PEM formatted key file.


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

Read a key:

```txt
$ ./tmtool read
~~ TrustM initinialised
~~ Key at slot 0xe0e8
[be, de, 82, f5, 6, 16, f6, 79, d3, 10, e6, a0, 47, fb, 44, bf, 34, 56, ee, 71, 33, 4c, 42, c5, a6, f0, b,
 a0, 3, e8, 7a, a6, c3, 57, fa, 84, fe, 65, d8, c5, 95, b4, b3, 17, b1, 9d, 63, 8b, 7a, 87, ba, f9, 4f, 65
, 89, 99, 37, e4, 42, 34, 13, 50, a4, 1a]
```

Write a key:

```txt
$ ./tmtool write  --key pk.pem
~~ TrustM initinialised
~~ Parsed key at "pk.pem"
~~ Key successfuly written to slot 0xe0e8
```
