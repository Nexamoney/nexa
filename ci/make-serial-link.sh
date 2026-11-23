#!/bin/sh
# Run from the configured build directory. Recursive makes share its lock.
set -eu
export NEXA_LINK_DIR="$PWD"

# Automake puts these prefixes directly before its link commands.
# Keep the trailing space so flock and the command are separate arguments.
link_prefix='flock "$$NEXA_LINK_DIR" '
exec make "$@" "AM_V_CCLD=$link_prefix" "AM_V_CXXLD=$link_prefix" "AM_V_OBJCXXLD=$link_prefix"
