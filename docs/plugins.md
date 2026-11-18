# Plugins

A plugin reads the neighbor table of another host, a router usually, every `interval`, and registers its entries: it finds the hosts of networks the local discovery doesn't reach, as other VLANs, or all of them where the local discovery can't run.

```
ipv6disc -plugin "router=linux:interval=60s,address=192.168.1.1,username=root,identity_file=/key,host_key=SHA256:..."
```

`-plugin` can be given several times, for several hosts. The types, `linux`, `freebsd` and `mikrotik`, their params, and how to write them, are in the [plugins reference](reference/plugins.md).

## What they register

The tables of the families on: IPv6 neighbors, and with `-ipv4` the ARP tables too. Only the entries confirmed recently: a router can keep an entry long after its host left, and the addresses of hosts that left must expire. Each address is registered with the plugin's name as its source.

## SSH host keys

Give a `linux` or `freebsd` plugin its `host_key`, so that nobody in between can pass for the host. To get it, from a trusted network:

```
ssh-keyscan -t ed25519 192.168.1.1 | ssh-keygen -lf -
```

## A Mikrotik user

The plugin only reads, so give it a user of its own, with the `read` and `api` policies, limited to the address it connects from:

```
/user group add name=ipv6disc policy=read,api
/user add name=ipv6disc group=ipv6disc address=192.168.88.10/32 password=...
```

The `api` service, or `api-ssl` with `use_tls=true`, must be on, under `/ip/service`.

## Writing one

A plugin implements `ipv6disc.Plugin`, and registers its type in `init` with `plugins.Register`, its params with their descriptions: the flags take them, the [reference](reference/plugins.md) is made of them, and `plugins.FieldParams` builds the params of programs that have them as fields. The plugins of [`pkg/plugins`](../pkg/plugins) are the examples.
