# IPv6 Host Discovery

This program scans the local network and discovers IPv6 hosts addresses.

## Installation

Ensure you have Go installed on your system. If not, follow the instructions on the official [Go website](https://golang.org/doc/install) to install it.

## Usage

By default it will output the discovered hosts as json messages to `stdout`. You can easily parse the output with [`jq`](https://stedolan.github.io/jq/).
```
ipv6disc | jq 'select(.msg == "host identified") | .ipv6,.iface'
```

Alternatively, using `-live` the data will be displayed on the screen in a human readable form.

If you need to pause and select/copy data use `screen`, launch `ipv6disc -live [...]` and press `Ctrl+a` and then `ESC` to enter copy mode. When finished `ESC` again will continue updating.

### Flags

- `-log_level`: Set the logging level (default: "info"). Available options: "debug", "info", "warn", "error", "fatal", "panic".
- `-ttl`: Set the time-to-live (TTL) for a discovered host entry in the table after it has been last seen (default: 4 hours). This is not the TTL of the DDNS record.
- `-live`: Show the current state live on the terminal (default: false).

## License

This project is licensed under Apache License 2.0 

It uses libraries from the following projects:
- github.com/google/uuid - BSD 3-Clause License
- github.com/mdlayher/ndp - MIT License
- github.com/nsf/termbox-go - BSD 2-Clause License
- go.uber.org/zap - MIT License
- golang.org/x/net - BSD 3-Clause License
