# mldspy

Watch Multicast Listener Discovery (MLDv2) messages on the wire.

![](https://raw.githubusercontent.com/brettsheffield/mldspy/master/screenshot.png)

## Installation

```
make
make install
```

Creating a raw socket requires CAP_NET_RAW. As an alternative to installing
setuid, give the executable this capability:

`setcap cap_net_raw=eip /path/to/mldspy`

## Usage

`mldspy [--debug] [--noexpire]`

**--debug** - increase logging level

**--noexpire**  - don't expire group or source records from cache

## Authors

Brett Sheffield

## License

This program is licensed under GPLv2 or any later version.

## Bugs

Please raise an issue at https://github.com/brettsheffield/mldspy/issues
