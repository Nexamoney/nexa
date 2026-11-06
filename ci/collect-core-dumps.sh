#!/usr/bin/env bash
printf 'core_pattern after tests: '
cat /proc/sys/kernel/core_pattern
mkdir -p "$CI_PROJECT_DIR/cores/from-tmp" || exit 1
if [ -d /tmp/cores ]; then
    cp -a /tmp/cores/. "$CI_PROJECT_DIR/cores/from-tmp/"
fi
