# 11. Prompt E: libvirt lab automation (operator-supplied, 2026-11-21)

Context: use the guardrail block and the kickoff prompt. Implement lab_automation/ for an Omarchy (Arch Linux) host with libvirt/QEMU/KVM
and a Windows 10 guest reached over SSH.

Operator-supplied settings (put in lab_automation/lab_config.yaml; ask for any missing value):
- base_image: path to the shut-down baseline qcow2 (read-only; placed in /var/lib/libvirt/images/ or a directory traversable by the libvirt/qemu user; never booted directly after baseline)
- domain_xml_template: path to a libvirt XML template (vcpus 4, memory 6 to 8 GB, qcow2 disk, isolated network, fixed MAC address)
- network_name: an isolated libvirt network (no <forward> element)
- guest_ip (static IP in guest or fixed-MAC DHCP lease), ssh_user (Administrator privs), ssh_key_path
- post_ssh_settle_seconds: 20 (mandatory wait after SSH becomes reachable so Windows cold-boot tasks finish before launchers start)
- run_output_dir on the host

Design:
1. Fresh state per run without modifying base: create a throw-away overlay
     qemu-img create -f qcow2 -F qcow2 -b <base_image> <overlay_path>
   define a transient domain from the XML template pointing at the overlay (virsh create), and delete the overlay after the run.
   This is the "revert". The base image is never written.
2. Wait for SSH with a timeout, then sleep `post_ssh_settle_seconds` (default 20s) so boot-time scheduled tasks settle. Fail the run cleanly if the guest never comes up.
3. GuestRunner interface with an SSH implementation (ssh/scp via subprocess or paramiko). Keep an optional qemu-guest-agent implementation behind the same interface.
4. Interleaving: start the benign launcher and the attack launcher as two separate SSH sessions in parallel threads, with a seeded random start offset (0 to 20 s)
   and seeded random step ordering. Neither launcher starts before the other has been scheduled; there is no benign-only period before the attack.
   Record the wrapper PIDs of the SSH launchers so `sshd.exe` and the outer runner shell PIDs can be added to `config.RUNNER_EXCLUDE_PATHS` / `RUNNER_EXCLUDE_PIDS` and never pollute process lineage features.
5. Host-side provenance log, one JSONL per run (lab_automation/provenance/<run_id>.jsonl): run_id, launcher, timestamp, action, expected artifact keys, seed.
   Never copy it into the guest.
6. After both launchers finish (or time out), wait 5 seconds for event/prefetch flush, run collector/Collect-Artifacts.ps1 in the guest, scp the output directory to data/raw/runs/<run_id>/, then
   shut down (virsh shutdown, then virsh destroy after a timeout) and delete the overlay.
7. Control runs: a mode that boots a fresh overlay, waits `post_ssh_settle_seconds`, does nothing for the average run duration, and collects. Run at least 3 control boots; the union of their artifacts is the baseline set B
   (it captures boot-time drift).
8. run_all.py: reads techniques.yaml (technique_id, tactic, split, variants), builds the run list (45 to 65 runs), supports --resume, retries a failed run once, logs
   failures and continues, aborts if free disk is below 30 GB, and writes a run table (run_id, technique, variant, status, duration).
9. techniques.yaml parameterises every payload so no forbidden token (see doc 10) appears in artifact names or values. Render commands on the host from the
   chosen atomic definitions and send them to the guest through a neutral wrapper; do not install the Atomic module in the guest unless the operator says so.
   If the module must run in the guest, its folder and logs go into config.RUNNER_EXCLUDE_PATHS.
10. Network: runs use the isolated network. Prerequisite staging (while online) is a separate, manual step by the operator.
11. Dry-run mode: 3 runs (one dev technique, one holdout technique, one control) end to end, with timings printed.

Tests: unit tests for run-list generation, overlay command construction (mock subprocess), seeded interleaving determinism, and resume logic.
Do not claim the live path works until the operator has run the dry run and pasted the output.
