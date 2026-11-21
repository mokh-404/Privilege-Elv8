# Lab Automation (Windows 11 + libvirt / QEMU / KVM)

Host-side run orchestration implementing Prompt E (`docs/11_prompt_E_libvirt.md`) adapted for the persistent `win11` domain (`qemu:///system`, UEFI Secure Boot + `swtpm` 2.0).

## Setup
1. Copy `lab_config.example.yaml` -> `lab_config.yaml` (gitignored) and fill `guest_ip`, `network_name`, and `ssh_key_path`.
2. Ensure the `win11` domain is shut off, `/var/lib/libvirt/images/win11_base.qcow2` is read-only (`chmod 444`), and `/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base` exists.
3. Confirm the 5 proposed holdout techniques in `techniques.yaml` (`python -m lab_automation.run_all --propose-holdout`) before freezing and launching runs.

## Dry Run (3 runs: 1 control, 1 dev, 1 holdout)
```bash
.venv/bin/python -m lab_automation.run_all --dry-run
```

## Full Batch (51 runs: 3 controls + 48 technique variants, resumable)
```bash
.venv/bin/python -m lab_automation.run_all --resume
```
