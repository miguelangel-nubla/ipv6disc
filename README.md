# IPv6 Host Discovery

This program scans the local network and discovers IPv6 hosts addresses.
It needs to be executed as superuser to be able to listen on the required ports.

Used by [ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns)

## Installation

Download the [latest release](https://github.com/miguelangel-nubla/ipv6disc/releases/latest) for your architecture.

### Or build from source

Ensure you have Go installed on your system. If not, follow the instructions on the official [Go website](https://golang.org/doc/install) to install it. Then:
```
go install github.com/miguelangel-nubla/ipv6disc
```

### Or use the docker image
This may or may not work on your system. I was able to make it work with host networking and without `ipv6:true` in `/etc/docker/daemon.json`???. If you have experience and can help with ipv6 docker please let me know.
```
docker run -it --rm --network host gcr.io/miguelangel-nubla/ipv6disc -live
```

## Usage

By default, it will output the discovered hosts as JSON messages to `stdout`. You can easily parse the output with [`jq`](https://stedolan.github.io/jq/).

>:warning: This utility needs to be executed as a superuser to be able to listen for IPv6 ICMP packets.

```
sudo ipv6disc | jq 'select(.msg == "host identified") | .ipv6,.iface'
```

Alternatively, using `-live` the data will be displayed on the screen in a human-readable form.

If you need to pause and select/copy data use `screen`, launch `ipv6disc -live [...]` and press `Ctrl+a` and then `ESC` to enter copy mode. Now you can use the mouse to copy text. When finished `ESC` again will continue updating.

## Flags

- `-log_level`: Set the logging level (default: "info"). Available options: "debug", "info", "warn", "error", "fatal", "panic".
- `-ttl`: Set the time-to-live (TTL) for a discovered host entry in the table after it has been last seen (default: 4 hours).
- `-live`: Show the current state live on the terminal (default: false).

## License

This project is licensed under Apache License 2.0 

It uses libraries from the following projects:
- github.com/google/uuid - BSD 3-Clause License
- github.com/mdlayher/ndp - MIT License
- github.com/nsf/termbox-go - MIT License
- go.uber.org/zap - MIT License
- golang.org/x/net - BSD 3-Clause License
