# Plugins

A plugin reads the neighbor table of another host, a router usually, every `interval`, and registers its entries: it finds the hosts of networks the local discovery doesn't reach, as other VLANs, or all of them where the local discovery can't run.

```
ipv6disc -plugin "router=linux:interval=60s,address=192.168.1.1,username=root,identity_file=/key,host_key=SHA256:..."
```

`-plugin` can be given several times, for several hosts. The spaces around a param are dropped, so there can be one after each comma, but those of the password, which are its own; the names are case-insensitive. The types, `linux`, `freebsd` and `mikrotik`, their params, and how to write them, are in the [plugins reference](reference/plugins.md).

## What they register

The tables of the families on: IPv6 neighbors, and with `-ipv4` the ARP tables too. Only the entries confirmed recently: a router can keep an entry long after its host left, and the addresses of hosts that left must expire. Each address is registered with the plugin's name as its source.

Only hosts: the multicast groups a Mikrotik router lists among its neighbors are left out. A link-local address comes from the other host with that host's interface as its zone, `fe80::1%em0`: the zone is dropped, never taken for an interface of this machine.

A poll takes 30 seconds at most, connecting included: a host that doesn't answer is an error of that poll, and the next one runs at its time. Stopping the program stops the poll under way, which is not reported as an error.

## SSH host keys

Give a `linux` or `freebsd` plugin its `host_key`, so that nobody in between can pass for the host. To get it, from a trusted network:

```
ssh-keyscan 192.168.1.1 | ssh-keygen -lf -
```

A host usually has several keys, one of each kind, and this lists them all: the fingerprint of any of them works. The plugin asks the host for its key of each kind until it shows the one given, and remembers which it was. A host that has none with that fingerprint is refused, with the fingerprints it showed in the error, before the password or the command is sent to it.

Without `host_key` any key is accepted, and the log warns once, after the first poll that succeeds, with the fingerprint the host showed.

## A Mikrotik user

The plugin only reads, so give it a user of its own, with the `read` and `api` policies, limited to the address it connects from:

```
/user group add name=ipv6disc policy=read,api
/user add name=ipv6disc group=ipv6disc address=192.168.88.10/32 password=...
```

The `api` service, or `api-ssl` with `use_tls=true`, must be on, under `/ip/service`. Without `use_tls=true` the password crosses the network in the clear. `use_tls` is `true` or `false`, anything else is an error, and so is a `tls_fingerprint` without `use_tls=true`: it would not be checked.

With `use_tls=true` alone, the router's certificate is verified with the system's CAs, for the name or address in `address`. The certificate RouterOS makes for itself is self-signed, and the Docker image has no CAs at all: there, give its `tls_fingerprint`, which is then all that is checked:

```
openssl s_client -connect 192.168.88.1:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

In the image, a certificate of a public CA is verified with the host's CAs mounted in instead: `-v /etc/ssl/certs:/etc/ssl/certs:ro`.

## Writing one

A plugin implements `ipv6disc.Plugin`, and registers its type in `init` with `plugins.Register`, its params with their descriptions: the flags take them, the [reference](reference/plugins.md) is made of them, and `plugins.FieldParams` builds the params of programs that have them as fields. The plugins of [`pkg/plugins`](../pkg/plugins) are the examples. `plugins.Describe` only gives a type its description: it is `plugins.Register` that makes it one.

`plugins.Poller` runs the polls and keeps their stats: its `Run` needs a positive interval, and returns an error otherwise, as `Start` of the plugins here does for a config built by hand without one.
