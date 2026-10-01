#!/usr/bin/env sh
set -eu

#
# Install and use the project toolchain with Docker.
#
# Run with the argument `help` for usage information.
#

if [ $# -eq 0 ]; then
  docker compose up --detach
  docker compose exec typenet nix develop .#docker
  exit
fi

case "$1" in

down) docker compose down ;;

clean) docker compose down --volumes --rmi all ;;

h | help | -h | --help)
  echo "Usage:

$0        # Start a shell in the container, building as necessary
$0 down   # Remove the container and network
$0 clean  # Remove the container, network, volume, and image
"
  ;;

esac
