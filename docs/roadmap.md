# Roadmap (public `fray`)

## v0.6 — prebuilt Action binaries

Ship release binaries with checksums and artifact attestation. The GitHub
Action downloads and verifies the matching binary instead of `go build` in CI
(faster runs; no Go toolchain required on the runner for the scan path).
