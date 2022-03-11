
# we can use the filename in test descriptions
FILE="$(basename "${BATS_TEST_FILENAME}" .bats):"
export FILE

# shellcheck disable=SC2154
stderr() {
    printf '%s' "$stderr"
}
export -f stderr

# shellcheck disable=SC2154
output() {
    printf '%s' "$output"
}
export -f output

