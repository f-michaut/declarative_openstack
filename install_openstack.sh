#!/bin/env bash

# TODO check permissions on /etc/project/* files since they contain passwords

set -euo pipefail
set -x

SCRIPT_DIR=${SCRIPT_DIR:="$(dirname -- "$(realpath -- "$0")")"}

stealth_eval() {
    { local -; set +x; } 2> /dev/null

    eval "$@"
}

prompt() {
    while 1; do
        read -r -n1 -p "$* (Y/n)" yn
        case $yn in
            "") return 0;;
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
done
}

check_os_version() {
    set -a
    { source /etc/os-release; } 2> /dev/null
    set +a
    [[ "${NAME:-}" == "$1" && "${VERSION_ID:-}" == "$2" ]]
}

main() {
    # TODO
    # if ! check_os_version Ubuntu 20.04
    # then
    #     echo "This script can only be run on Ubuntu 20.04 LTS." >&2
    #     exit 3
    # fi

    # if [ "$(id -u)" != "0" ]
    # then
    #     echo "Please run as root" >&2
    #     exit 2
    # fi

    if ! env python3 <<EOF;
import yaml
EOF
    then
        if prompt "python3: pyyaml module not found, do you want to install it ?";
        then
            pip3 install pyyaml
        else
            echo "Missing pyyaml, cannot continue." >&2
            return 1
        fi
    fi
    python3 "$SCRIPT_DIR/scripts/parse_yaml.py" "./config.yaml.exemple" # TODO
}

main "$@"
