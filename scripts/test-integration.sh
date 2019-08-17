#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_DIR="${SCRIPT_DIR}/.."
cd "$REPO_DIR"

ginkgo -randomizeAllSpecs test/integration
