# Sandbox Image — Minimal-PATH Hardening

The `docker/Dockerfile.sandbox` builds a hardened base image for
Ring-3 (Sandbox) agent workloads.  `PATH` is pinned to a single
curated directory (`/usr/local/sandbox/bin`) that contains only the
explicitly approved binaries listed in the Dockerfile and in
`hypervisor.sandbox.ALLOWED_BINARIES`.  Denied binaries (network
fetch tools, alternative interpreters, compiler toolchain, and shells)
are removed from their original filesystem locations so they cannot be
reached by absolute path even if code tries to bypass `PATH`.

## Extending the allowed-binary list

To add a new binary to the sandbox image:

1. **Update the constants** in
   `src/hypervisor/sandbox/__init__.py`:
   add the binary name to `ALLOWED_BINARIES` and remove it from
   `DENIED_COMMANDS` if it was listed there.  Document *why* the
   binary is needed (e.g. "jq — required for JSON post-processing in
   the data-pipeline workload").

2. **Update the Dockerfile** in `docker/Dockerfile.sandbox`:
   add a `ln -s` line inside the "Create the curated sandbox bin
   directory" `RUN` block, pointing at the resolved path of the
   binary, for example:

   ```dockerfile
   && ln -s "$(command -v jq)" /usr/local/sandbox/bin/jq \
   ```

   If the binary is not present in the base image, install it with
   `apt-get install --no-install-recommends` *before* the curated-bin
   `RUN` step, using an exact version pin.

3. **Re-run the smoke tests** to confirm consistency:

   ```bash
   pytest agent-governance-python/agent-hypervisor/tests/unit/test_sandbox_path.py -v
   ```

4. **Rebuild the image** and run the end-to-end container smoke test:

   ```bash
   docker build \
     -f agent-governance-python/agent-hypervisor/docker/Dockerfile.sandbox \
     -t hypervisor-sandbox .
   docker run --rm hypervisor-sandbox \
     python3 -c "import shutil; assert shutil.which('jq') is not None"
   ```

Keep the allowed list as short as possible.  Every additional binary
widens the attack surface available to a sandboxed agent.
