# Flipside.AI Topology

A Node.js app for mapping an office network, checking connectivity, and collecting authorized device audits.

## Host it on a branch PC

Install [Node.js 18 or newer](https://nodejs.org/) and Git on the PC that will host the app. Clone this repository and install its dependencies:

```sh
git clone https://github.com/keithmarkreel/office-network-lab.git
cd office-network-lab
npm install
```

Start the server so it accepts connections from other PCs on the branch network.

**Linux or macOS**

```sh
HOST=0.0.0.0 PORT=3000 npm start
```

**Windows PowerShell**

```powershell
$env:HOST = "0.0.0.0"
$env:PORT = "3000"
npm start
```

Keep the terminal open while the app is in use. Find the host PC's private network IP (`ipconfig` on Windows, `hostname -I` on Linux), then coworkers on the same trusted network can open `http://HOST-PC-IP:3000` in a browser. For example: `http://192.168.1.25:3000`. For another branch, use company-approved VPN or private network routing; the host must be reachable over that connection.

If coworkers cannot connect, allow inbound TCP port 3000 through the host PC's firewall for the **Private** network only, and check that branch network rules allow connections between their PCs. Do not use port forwarding to expose the app to the internet.

## What coworkers can do

The floor plan is saved on the host PC in `data/office-plan.json`, so users connecting to that host share and can edit the same plan. Each branch should run its own copy if its floor plan and audit data must remain separate.

Ping, subnet scans, and SSH scans run from the host PC. For security, SSH login tests, audit runs, provisioning, and CSV downloads are restricted to a browser on the host PC itself; coworkers connecting remotely cannot use those actions. Remote users can still edit the plan and use the features available to them in the UI.

## Optional tools

- Ping requires the system `ping` utility.
- SSH scans require Nmap on the host PC.
- SSH login checks and remote audit features require the installed `ssh2` dependency (`npm install`).
- Audit collection and PC provisioning require a **Linux host PC** and target PCs configured for `scanlog` SSH access. Use the in-app setup instructions and only audit systems you are authorized to administer.

## Updates and data

To update a branch installation, stop the server with Ctrl+C, then run:

```sh
git pull
npm install
npm start
```

Back up the host PC's `data/` folder. It contains the shared floor plan, SSH host-key pins, audit reports, and tracking-sheet CSVs, and is excluded from Git.

## Security

The app has no user accounts or team authentication. Anyone who can reach it on the branch network can view and change its floor plan. Bind it to a trusted private network only, restrict firewall access to intended users, and do not expose it to the internet or an untrusted network.
