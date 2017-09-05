#!/bin/bash

set -x

cd $KOKORO_ARTIFACTS_DIR/git/gocloud

# Run test only if profiler directory is touched.
profiler_test=false
for f in $(git diff-tree --no-commit-id --name-only -r HEAD); do
  if [[ "$(dirname $f)" == "profiler" ]]; then
  	profiler_test=true
  fi
done

if [[ "$profiler_test" = false ]]; then
	exit 0
fi

commit=$(git rev-parse HEAD)

# Run test only if service account key exists.
if [[ ! -e "$KOKORO_KEYSTORE_DIR/72523_encrypted_ba2d6f7723ed_key" ]]; then
	exit 0
fi

cd $GOCLOUD_HOME/internal/kokoro
# Don't print out encryption keys, etc
set +x
key=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_key")
iv=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_iv")
pass=$(cat "$KOKORO_ARTIFACTS_DIR/keystore/72523_encrypted_ba2d6f7723ed_pass")

openssl aes-256-cbc -K $key -iv $iv -pass pass:$pass -in kokoro-key.json.enc -out key.json -d
set -x

export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/key.json"

cd $GOCLOUD_HOME/profiler
go get -t -tags=integration .
go test -timeout=60m -parallel=5 -tags=integration -run TestAgentIntegration -commit="$commit"
