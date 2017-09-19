#!/bin/bash

# Fail on any error
set -eo pipefail

# Display commands being run
set -x

source git/gocloud/profiler/integration-test.sh .
