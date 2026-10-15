#!/usr/bin/env bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the Swift HTTP Server open source project
##
## Copyright (c) 2026 Apple Inc. and the Swift HTTP Server project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of Swift HTTP Server project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

# Compares NIOHTTPServer with the PlatformHTTPServer using h2load.
#
# Both implementations run in the same HTTPServerBenchmark binary with the same handler, certificate and thread count.
# For every scenario the script starts one implementation, runs h2load a number of times against it, and prints the
# median requests per second.
#
# Usage:
#   Scripts/compare-http-servers.sh [path to HTTPServerBenchmark]
#
# Environment:
#   RUNS      Runs per scenario and implementation. Default 3.
#   THREADS   Threads of the server. Default 1.
#   PORT      Port of the server. Default 18443.
#   H2THREADS Threads of h2load. Default 2.
#   DYLD_LIBRARY_PATH may have to point at the Concurrency runtime of the toolchain that built the binary.

set -euo pipefail

BINARY="${1:-.build/release/HTTPServerBenchmark}"
RUNS="${RUNS:-3}"
THREADS="${THREADS:-1}"
PORT="${PORT:-18443}"
H2THREADS="${H2THREADS:-2}"

# name:response size:connections:streams per connection:requests
SCENARIOS=(
  "small-16x10:15:16:10:200000"
  "small-100x100:15:100:100:300000"
  "body-16KiB:16384:16:10:100000"
  "body-1MiB:1048576:8:8:3000"
)

median() {
  sort -n | awk '{ v[NR] = $1 } END { if (NR == 0) { print "n/a" } else { print v[int((NR + 1) / 2)] } }'
}

run_scenario() {
  local implementation=$1 size=$2 connections=$3 streams=$4 requests=$5
  "$BINARY" --implementation "$implementation" --port "$PORT" --threads "$THREADS" --response-size "$size" \
    >/tmp/compare-http-servers-"$implementation".log 2>&1 &
  local server=$!
  trap 'kill $server 2>/dev/null || true' RETURN
  sleep 2

  local rates=() failures=0
  for _ in $(seq "$RUNS"); do
    local output
    output=$(h2load -n "$requests" -c "$connections" -m "$streams" -t "$H2THREADS" "https://127.0.0.1:$PORT/" 2>&1 || true)
    local rate failed
    rate=$(echo "$output" | awk '/finished in/ { for (i = 1; i <= NF; i++) if ($i == "req/s,") print $(i - 1) }')
    failed=$(echo "$output" | awk '/^requests:/ { for (i = 1; i <= NF; i++) if ($i == "failed,") print $(i - 1) }')
    rates+=("${rate:-0}")
    failures=$((failures + ${failed:-0}))
  done
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
  trap - RETURN

  local med
  med=$(printf '%s\n' "${rates[@]}" | median)
  echo "$med $failures"
}

printf '%-16s %-10s %14s %9s\n' "scenario" "impl" "median req/s" "failed"
for scenario in "${SCENARIOS[@]}"; do
  IFS=: read -r name size connections streams requests <<<"$scenario"
  for implementation in nio platform; do
    read -r med failures < <(run_scenario "$implementation" "$size" "$connections" "$streams" "$requests")
    printf '%-16s %-10s %14s %9s\n' "$name" "$implementation" "$med" "$failures"
  done
done
