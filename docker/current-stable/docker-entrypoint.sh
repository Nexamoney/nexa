#!/bin/bash
set -e

if [[ "$1" == "nexa-cli" || "$1" == "nexa-tx" || "$1" == "nexad" || "$1" == "test_nexa" ]]; then
  mkdir -p "$NEXA_DATA"

  if [[ ! -s "$NEXA_DATA/nexa.conf" ]]; then
    echo "printtoconsole=1" > "$NEXA_DATA/nexa.conf"
    # Open RPC beyond the container only when the user chose a password. Otherwise nexad keeps RPC on
    # loopback with cookie auth (docker exec -u nexa <container> nexa-cli ...).
    if [[ -n "$NEXA_RPC_PASSWORD" ]]; then
      cat <<EOF >> "$NEXA_DATA/nexa.conf"
rpcallowip=::/0
rpcpassword=${NEXA_RPC_PASSWORD}
rpcuser=${NEXA_RPC_USER:-nexa}
EOF
    fi
    chown nexa:nexa "$NEXA_DATA/nexa.conf"
    chmod 600 "$NEXA_DATA/nexa.conf"
  fi

  # ensure correct ownership and linking of data directory
  # we do not update group ownership here, in case users want to mount
  # a host directory and still retain access to it
  chown -R nexa "$NEXA_DATA"
  ln -sfn "$NEXA_DATA" /home/nexa/.nexa
  chown -h nexa:nexa /home/nexa/.nexa

  exec gosu nexa "$@"
fi

exec "$@"
