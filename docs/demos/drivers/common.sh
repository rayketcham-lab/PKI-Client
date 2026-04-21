# shellcheck shell=bash
# Common helpers for pki demo drivers.
#
# Set PKI_BIN to the built binary before running a driver, e.g.:
#   PKI_BIN=$(pwd)/target/release/pki bash docs/demos/drivers/cert-inspect.sh
# or record a cast:
#   asciinema rec --overwrite -c "bash docs/demos/drivers/cert-inspect.sh" \
#     docs/demos/cert-inspect.cast

PKI_BIN="${PKI_BIN:-pki}"
PROMPT="\033[1;36m$\033[0m"

# Simulate typing by printing characters with a short delay between each.
type_cmd() {
  local text="$1"
  printf "%b " "$PROMPT"
  local i=0
  while [[ $i -lt ${#text} ]]; do
    printf "%s" "${text:$i:1}"
    sleep 0.02
    i=$((i + 1))
  done
  printf "\n"
}

# Print prompt + command, then run it.
run() {
  type_cmd "$*"
  sleep 0.3
  "$@"
  sleep 0.8
}

# Run a command through bash (for shell syntax like pipes).
run_sh() {
  type_cmd "$1"
  sleep 0.3
  bash -c "$1"
  sleep 0.8
}

# Narration comment line.
note() {
  printf "\n\033[1;33m# %s\033[0m\n" "$1"
  sleep 0.6
}
