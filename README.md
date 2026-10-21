# Flipside.AI Topology

A Node.js app for mapping an office network, checking connectivity, and collecting authorized device audits.

## Feature walkthrough

The app is a **Packet Tracer-style visual map**, not a network simulator: it helps document a real office layout and check real devices, but it does not create links, configure routers, or simulate packet flow.

### Map the office

1. Choose **Add PC**, **Add router**, **Add U-desk**, **Add table**, or **Add room**.
2. Drag items into place on the canvas. Select an item to edit its name, IP address, and other details in the side panel.
3. Device addresses and audit targets are expandable, searchable, and paginated at eight entries per page. Select a PC to see its status and controls. Use **Hide IPs** to hide addresses on screen; this does not change saved data.
4. Changes are saved automatically. Copy the selected item with Ctrl/Cmd+C and paste with Ctrl/Cmd+V. Copies of PCs and routers have their IP cleared.

### Check connectivity and find SSH hosts

1. Select a PC with an IP address and choose **Check connectivity** to send one ping from the app host. No reply may mean the device is offline or blocking ping.
2. To discover SSH-enabled hosts, enter a private IPv4 network in **Private subnet** (for example, `192.168.1.0/24`) and choose **Scan subnet**. Scans support `/24` through `/30` and run from the app host using Nmap.
3. Expand **Audit targets** to search discovered hosts and mapped PCs. **Test SSH** checks a discovered host's password login as `scanlog`; an open SSH port alone does not guarantee login access.

### Collect audits

1. In **Audit targets**, select the PCs you are authorized to audit. Use **Select all targets** or **Clear selection** as needed.
2. Choose **Collect logs** for inventory and audit reports, or **Collect + ClamAV scan** to include an optional read-only scan of target home folders. All selected PCs are processed simultaneously; large selections can increase network and host load.
3. Enter the requested one-time `scanlog` sudo password. It is not saved. Use **Setup instructions** and **Provision selected PCs** if targets need the audit collector; provisioning makes persistent changes to those PCs and requires confirmation.
4. Choose **Download tracking-sheet CSV** to export the current month's tracking-sheet rows.

Ping and scans run from the app host. SSH login tests, audit runs, provisioning, and CSV downloads require a browser on the host PC. The in-app **Quick tour** also gives a step-by-step overview.

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
