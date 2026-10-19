# Office floor plan

A small Node.js app for editing and saving an office floor plan.

## Run

Install Node.js 18 or newer, then start the app:

```sh
npm start
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). Set `PORT` or `HOST` to change the address.

## Security

This app is intended for local use on a trusted IT workstation. It does not provide user accounts or team authentication. Do not expose it directly to the internet or an untrusted network. Network scans, SSH checks, provisioning, and audit collection run with the app server's network access and privileges. Keep the app host and its `data/` directory restricted to authorized administrators.

Local floor-plan state, SSH host-key pins, audit output, and tracking-sheet CSVs are stored under `data/` and are excluded from Git.

Changes are autosaved to `data/office-plan.json` on the server. The editor supports dragging, resizing, rotating, duplicating, copying, pasting, and deleting rooms, desks, tables, PCs, and routers. Use Ctrl/Cmd+C and Ctrl/Cmd+V to copy and paste the selected item; the toolbar has no copy/paste buttons. Pasted PCs and routers have their IP cleared to avoid duplicate addresses. Device addresses and audit targets are collapsed into expandable, searchable lists to keep the floor plan uncluttered; devices are sorted by name, and search matches visible names and IP addresses. Use **Hide IPs / Show IPs** to control whether device IPs appear in the topology, device list, scan and audit results, and selected-device panel. This display preference is saved in the browser and does not change the saved addresses. The private subnet field used for scanning remains visible. Select a PC and enter its IP to use:

- **Check connectivity** sends one ICMP ping from the machine running the app. This only checks reachability; firewalls may block ping even when other services work. The app server needs the system `ping` utility.
- **Scan for SSH hosts** runs the same Nmap TCP-connect scan as the supplied script (`-sT -n -p22 --open`) from the app server. Enter a private IPv4 subnet from `/24` through `/30`; the default is `192.168.0.0/24`. Results identify hosts with TCP port 22 open and show which ones match PCs already on the floor plan. Install `nmap` on the app server to use this feature.
- From scan results, **Open mapped PC** selects the matching device on the floor plan, or **Test SSH** checks a discovered host directly. Starting an SSH test opens a masked password dialog for `scanlog`; the app uses password-only SSH and clears the password after one test. The password is not saved. First-use SSH host keys are pinned in `data/ssh-host-keys.json`; changed keys are rejected. The app server needs the Node.js `ssh2` dependency, installed by `npm install`.
- Password authentication must be enabled for `scanlog` by the target PC's SSH server configuration.
- **Audit collection** lets you select mapped PCs and hosts found by the SSH scan, then collect the supplied script's hardware inventory and authentication/system/app audit reports. Browser history is disabled. Each collection run asks once for the `scanlog` sudo password; it is used for the selected targets, sent to the app server only for that run, passed to each target over SSH, and not saved. **Collect + ClamAV scan** also scans the selected user home folders on targets; it is read-only but temporarily stops and restarts `clamav-freshclam` when active. Configure the log window and scan file-age window in the UI. Install Bash, Nmap, OpenSSH, and the script's standard Linux utilities on the app server; targets need the collector provisioned and key-based `scanlog` access.
- **Download tracking-sheet CSV** downloads the current month's tracking-sheet rows created during audit collection. The file is saved in the app host's `data/audit-results/<Month> Scan Logs/scan_log_<Month>.csv`; run an audit collection first if no CSV exists yet. Downloads are restricted to a browser on the app host.
- **Setup instructions** disclose the persistent target changes. **Provision selected PCs** requires typing `PROVISION` in the confirmation prompt, then asks for the `scanlog` SSH login and sudo passwords in the browser. The app installs its SSH public key for future collection, installs a root-owned collector, and replaces the existing `audit-collect` rule with a limited password-required sudo rule. Reprovision existing PCs to remove their old passwordless rule. The credentials are only used for that provisioning request and are not saved. The target must accept password-based SSH for `scanlog`; the sudo password can be different from its SSH password.

Audit results are saved under `data/audit-results`, with restrictive permissions, and the script's summary appears in the UI. Audit runs and results are restricted to a browser on the app host. The collector's separate remote execution channel uses the app host's SSH key plus the one-time sudo password; the SSH connectivity/login test uses its own password prompt. Use the collector only on systems you administer or are authorized to audit: authentication records and inventory can contain sensitive information. Ping and SSH test results are stored in the browser. Update and driver actions remain front-end demo controls and do not run commands on the PCs.
