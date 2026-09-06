# EV3 host benchmarks

`ev3_codec_session_benchmark.cpp` measures native direct/wrapped codec throughput and complete EV2 MAC request/verified-response state transitions. It uses fixed public payloads and the configured OpenSSL provider, performs no card or reader I/O, and caps iterations below the EV2 counter limit.

The executable reports host-local measurements without declaring a performance baseline. Release or CI jobs may opt into explicit acceptance limits with:

```text
ev3_codec_session_benchmark --iterations 20000 \
  --min-codec-mib-s <measured-policy-limit> \
  --min-session-ops-s <measured-policy-limit>
```

A missing threshold only reports the corresponding measurement. A supplied threshold that is not met exits with status 3. Establish platform-specific limits from controlled repeated measurements; do not reuse a workstation result as an embedded-reader requirement.

## CodSpeed integration

`ev3_codspeed_benchmark.cpp` expresses the same native-codec and EV2 MAC-session domains through
CodSpeed's Google Benchmark compatibility layer. It is opt-in so ordinary builds and source
packages do not download benchmark-only dependencies:

```sh
cmake -S . -B build/codspeed -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DDESFIRE_BUILD_CODSPEED_BENCHMARKS=ON \
  -DDESFIRE_BUILD_PCSC=OFF \
  -DDESFIRE_BUILD_C_API=OFF \
  -DDESFIRE_BUILD_CPP17=OFF \
  -DDESFIRE_BUILD_EXAMPLES=OFF \
  -DCODSPEED_MODE=simulation
cmake --build build/codspeed --target ev3_codspeed_benchmark --parallel
build/codspeed/tests/ev3_codspeed_benchmark
```

The dependency module pins CodSpeed C++ v2.4.0 to commit
`f5a917fdd14db7293bd37acb682873fec19f8b6c` and verifies the official release asset, including its
bundled instrument hooks, with SHA-256. The hosted workflow pins CodSpeed Action and runner v5.2.1,
grants read-only repository access, and uses CodSpeed's public-repository tokenless upload.

CodSpeed supplies stable pull-request comparisons and profiles after the public repository is
imported into CodSpeed. Configure the CodSpeed project threshold to 5% and approve its initial
baseline before treating its performance check as a merge gate. It does not replace
`ev3_codec_session_benchmark` or its caller-supplied thresholds; the controlled same-host release
gate becomes enforceable only after an approved platform-specific baseline exists.
