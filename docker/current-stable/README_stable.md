# Stable Nexa release docker containers

These are the needed files to build and publish the nexa docker image
for the current stable release.

## RPC access

On first start the entrypoint writes `/data/nexa.conf` if there is none.
By default RPC listens only inside the container and uses cookie
authentication, so use it with:

    docker exec -u nexa <container> nexa-cli getinfo

To reach RPC from outside the container, set `NEXA_RPC_PASSWORD` (and
optionally `NEXA_RPC_USER`, default `nexa`) on the first start. The
password must not contain `#`, which starts a comment in `nexa.conf`. RPC then
accepts connections from any address, so publish port 7227 only to
networks you trust.

An existing `/data/nexa.conf` is never rewritten. Volumes created by
older images contain `rpcpassword=password` unless `NEXA_RPC_PASSWORD`
was set: change or remove those lines.
