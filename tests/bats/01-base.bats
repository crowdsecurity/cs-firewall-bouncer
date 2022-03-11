#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "lib/setup_file.sh" >&3 2>&1
}

teardown_file() {
    load "lib/teardown_file.sh" >&3 2>&1
}

setup() {
    load "lib/setup.sh" >&3 2>&1
}

# ------------ #

@test "$FILE: always pass" {
    true
}

