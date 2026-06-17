# Inline NFQUEUE validation (incus)

Validates the kernel-level pieces that can't be tested without root + a live
kernel: the **nftables ruleset applying correctly** (the `ct state` set, `ct
packets`, `ct mark`, `queue ... bypass`, `@dpi_allow` rules) and **traffic
actually being inspected / banned / bypassed**.

Use a **VM, not a container** — NFQUEUE + nftables are kernel-level; a VM has its
own kernel and can't disturb the host.

## Topology

```
   incus host (client: curl / nmap)  ──TCP──►  VM "crmon" (crmonban, NFQUEUE input)
```
crmonban's queue rule matches *all* inbound TCP, so a test HTTP server on the VM
(or even its SSH) is enough to drive packets through the pipeline.

## Steps

```sh
# on the incus host (e.g. big02):
VM=crmon ./setup.sh                       # 1. launch VM + deps + rustup

# get the source onto the VM and build (private repo → push the tree, or git clone with your token):
incus file push -r ../../../crmonban crmon/root/   # or: incus exec crmon -- git clone ...
incus exec crmon -- bash -lc 'cd /root/crmonban && ~/.cargo/bin/cargo build --release'

# 2. install the test config + start crmonban (as root, in the VM):
incus file push crmonban-nfqueue.toml crmon/etc/crmonban/config.toml --create-dirs
incus exec crmon -- bash -lc 'cd /root/crmonban && ./target/release/<bin> --config /etc/crmonban/config.toml &'
#   ^ replace <bin>/flags with the real daemon invocation (e.g. `crmonban daemon` / `run`).

# 3. validate the ruleset applied (run inside the VM):
incus file push smoke-nft.sh crmon/root/ ; incus exec crmon -- bash /root/smoke-nft.sh

# 4. drive traffic + check inspect/ban/bypass (run on the incus host):
VM=crmon ./validate.sh
```

## Caveats

- The queue rule matches **all** inbound TCP, so the VM's **own SSH is also
  inspected**. A benign session is fine (inspected → accepted), but the port-scan
  test will **ban the scanner's source IP** — which is the incus host. If you SSH
  to the VM from that same IP you can lock yourself out; use `incus exec` (the
  agent, not SSH) for VM access, or run the ban test last / from a throwaway IP.
- `nfqueue_num` (engine) **must equal** `dpi.queue_num` (firewall) — both default
  100. The config here sets both.
- The nft set names (`blocked_v4`, etc.) come from `[nftables]` config defaults;
  the scripts grep by IP where possible so they don't depend on exact names.
- Reject verdicts currently collapse to silent Drop; forward/output queueing is
  not wired (input-chain only). See `docs/ARCHITECTURE.md` §9.
