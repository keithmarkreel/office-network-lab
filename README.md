# Flipside.AI Topology

A local Node.js app for mapping an office network, checking connectivity, and collecting authorized device audits.

## Run

Requires Node.js 18 or newer.

```sh
npm install
npm start
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). Set `PORT` to change the port.

## Features

- Add and arrange PCs, routers, desks, tables, and rooms. Changes save to the server automatically.
- Search the expandable device and audit-target lists. Hide IPs for a less cluttered view.
- Check PC reachability, scan private subnets for SSH, and test SSH login.
- Collect authorized audit reports, provision PCs, and download tracking-sheet CSVs.
- Copy and paste selected items with Ctrl/Cmd+C and Ctrl/Cmd+V. Copied PCs and routers have their IP cleared.

## Optional network tools

Ping requires the system `ping` utility. SSH scanning requires Nmap. SSH checks and remote audit features use the installed `ssh2` dependency (`npm install`); target PCs must allow SSH access for `scanlog`. The app provides setup instructions for audit provisioning. It uses one-time password prompts and pins SSH host keys.

## Data and security

Floor plans, SSH host-key pins, audit reports, and CSVs are stored in `data/` and excluded from Git. IP visibility is a browser preference and does not change saved addresses.

The app has no user accounts or team authentication. By default, it listens only on `127.0.0.1`. Do not expose it to the internet or an untrusted network. Network checks, scans, provisioning, and audits run from the app host; restrict access to the app and its `data/` directory. Only scan, provision, or audit systems you are authorized to administer.
