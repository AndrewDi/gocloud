// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build busybench

package profiler

import (
	"bytes"
	"compress/gzip"
	"flag"
	"log"
	"math/rand"
	"testing"
	"time"
)

var (
	target       = flag.String("target", "unknown", "target name")
	finishString = flag.String("finish_string", "busybench finished profiling", "finish string")
)

const duration = time.Minute * 10

// busywork continuously generates 1MiB of random data and compresses it
// throwing away the result.
func busywork() {
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			return
		default:
			busyworkOnce()
		}
	}
}

func busyworkOnce() {
	data := make([]byte, 1024*1024)
	rand.Read(data)

	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		log.Printf("failed to write to gzip stream", err)
		return
	}
	if err := gz.Flush(); err != nil {
		log.Printf("failed to flush to gzip stream", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("failed to close gzip stream", err)
	}
	// Throw away the result.
}

func TestBusy(t *testing.T) {
	defer func() {
		log.Printf(*finishString)
	}()
	err := Start(
		Config{
			Target:       *target,
			DebugLogging: true,
		})
	if err != nil {
		t.Fatalf("failed to start the profiler: %v", err)
	}
	busywork()
}
