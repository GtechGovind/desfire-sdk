# EV3 host benchmarks

`ev3_codec_session_benchmark.cpp` measures native direct/wrapped codec throughput and complete EV2 MAC request/verified-response state transitions. It uses fixed public payloads and the configured OpenSSL provider, performs no card or reader I/O, and caps iterations below the EV2 counter limit.

The executable reports host-local measurements without declaring a performance baseline. Release or CI jobs may opt into explicit acceptance limits with:

```text
ev3_codec_session_benchmark --iterations 20000 \
  --min-codec-mib-s <measured-policy-limit> \
  --min-session-ops-s <measured-policy-limit>
```

A missing threshold only reports the corresponding measurement. A supplied threshold that is not met exits with status 3. Establish platform-specific limits from controlled repeated measurements; do not reuse a workstation result as an embedded-reader requirement.
