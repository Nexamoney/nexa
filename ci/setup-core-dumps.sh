#!/usr/bin/env bash
# Keep both core destinations available while CI migrates to a fixed host pattern.
mkdir -p "$CI_PROJECT_DIR/cores" /tmp/cores || exit 1
ulimit -c unlimited || exit 1
printf 'core_pattern before tests: '
cat /proc/sys/kernel/core_pattern
