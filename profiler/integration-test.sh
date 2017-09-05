#!/bin/bash

# Fail on any error.
set -eo pipefail

# Display commands being run.
set -x

# cd to project dir on Kokoro instance
cd git/gocloud

# Run test only if profiler directory is touched.
PROFILER_TEST=false
for f in $(git diff-tree --no-commit-id --name-only -r HEAD); do
  if [[ "$(dirname $f)" == "profiler" ]]; then
    PROFILER_TEST=true
  fi
done

if [[ "$PROFILER_TEST" = false ]]; then
  exit 0
fi

commit=$(git rev-parse HEAD)

# Set $GOPATH
export GOPATH="$HOME/go"
GOCLOUD_HOME=$GOPATH/src/cloud.google.com/go
mkdir -p $GOCLOUD_HOME

# Move code into $GOPATH and get dependencies
cp -R ./* $GOCLOUD_HOME
cd $GOCLOUD_HOME
go get -v ./...

cd internal/kokoro
# Don't print out encryption keys, etc
set +x
key=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_key")
iv=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_iv")
pass=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_pass")

openssl aes-256-cbc -K $key -iv $iv -pass pass:$pass -in kokoro-key.json.enc -out key.json -d
set -x

export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/key.json"
export GCLOUD_TESTS_GOLANG_PROJECT_ID="dulcet-port-762"
export GCLOUD_TESTS_GOLANG_ZONE="us-west1-a"

cd $GOCLOUD_HOME/profiler
go get -t -tags=integration .
go test -timeout=60m -parallel=5 -tags=integration -run TestAgentIntegration -commit="$commit"
