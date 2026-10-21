import { createServer } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { createConnection, isIP } from 'node:net';
import { readFile, mkdir, rename, writeFile, chmod, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { Client } from 'ssh2';

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535');
}
const appDirectory = dirname(fileURLToPath(import.meta.url));
const pagePath = join(appDirectory, 'Office floor plan.html');
const stylesheetPath = join(appDirectory, 'styles.css');
const dataDirectory = join(appDirectory, 'data');
const dataPath = join(dataDirectory, 'office-plan.json');
const sshHostKeysPath = join(dataDirectory, 'ssh-host-keys.json');
const auditDirectory = join(dataDirectory, 'audit-results');
const auditScriptPath = join(appDirectory, 'audit-collector.sh');
const maxBodyBytes = 1_000_000;
const auditJobs = new Map();
let activeAuditJob = null;
const activeSshChecks = new Set();
let sshHostKeyWrite = Promise.resolve();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  response.end(JSON.stringify(body));
}

function isLoopbackRequest(request) {
  const address = request.socket.remoteAddress;
  return address === '::1' || address === '127.0.0.1' || address === '::ffff:127.0.0.1';
}

function isSameOriginRequest(request) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

function pingAddress(ip) {
  const platform = process.platform;
  let args;
  if (platform === 'win32') {
    args = ['-n', '1', '-w', '2500', ip];
  } else if (platform === 'darwin') {
    args = ['-n', '-c', '1', '-W', '2000', ip];
  } else {
    args = [...(isIP(ip) === 6 ? ['-6'] : []), '-n', '-c', '1', '-W', '2', ip];
  }

  return new Promise((resolve, reject) => {
    execFile('ping', args, { timeout: 3500, windowsHide: true, maxBuffer: 16_384 }, (error, stdout) => {
      if (error?.code === 'ENOENT') {
        reject(new HttpError(503, 'The ping utility is not installed on the app server'));
        return;
      }
      if (error?.killed) {
        resolve({ reachable: false, latencyMs: null, message: 'Ping timed out; no ICMP reply received' });
        return;
      }
      if (error) {
        resolve({ reachable: false, latencyMs: null, message: 'No ICMP reply; the device may be offline or blocking ping' });
        return;
      }
      const output = String(stdout);
      const latency = output.match(/time[=<]\s*([\d.]+)\s*ms/i);
      resolve({
        reachable: true,
        latencyMs: latency ? Number(latency[1]) : null,
        message: 'ICMP ping reply received'
      });
    });
  });
}

function validateScanSubnet(subnet) {
  const match = typeof subnet === 'string' && subnet.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match || isIP(match[1]) !== 4) {
    throw new HttpError(400, 'Enter an IPv4 private subnet between /24 and /30, such as 192.168.0.0/24');
  }

  const octets = match[1].split('.').map(Number);
  const prefix = Number(match[2]);
  if (prefix < 24 || prefix > 30) {
    throw new HttpError(400, 'Subnet scans are limited to /24 through /30 networks');
  }

  const address = octets.reduce((value, octet) => value * 256n + BigInt(octet), 0n);
  const mask = (0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn;
  if ((address & mask) !== address) {
    throw new HttpError(400, 'Enter the network address, not a host address');
  }

  const [first, second] = octets;
  const isPrivate = first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168);
  if (!isPrivate) {
    throw new HttpError(400, 'Subnet scans are limited to private IPv4 networks');
  }
  return `${match[1]}/${prefix}`;
}

function isPrivateIPv4(ip) {
  if (isIP(ip) !== 4) return false;
  const [first, second] = ip.split('.').map(Number);
  return first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168);
}

function validateAuditTargets(targets) {
  if (!Array.isArray(targets) || targets.length === 0 || targets.length > 254) {
    throw new HttpError(400, 'Select between 1 and 254 target PCs');
  }
  const uniqueTargets = [...new Set(targets)];
  if (uniqueTargets.length !== targets.length || uniqueTargets.some(ip => typeof ip !== 'string' || !isPrivateIPv4(ip))) {
    throw new HttpError(400, 'Audit targets must be unique private IPv4 addresses');
  }
  return uniqueTargets;
}

async function startAuditJob(mode, targets, logDays, scanDays, sudoPassword = '') {
  if (activeAuditJob) {
    throw new HttpError(409, 'An audit run is already in progress');
  }
  const id = randomUUID();
  const hostFile = join(auditDirectory, `.targets-${id}.txt`);
  activeAuditJob = id;
  try {
    await mkdir(auditDirectory, { recursive: true, mode: 0o700 });
    await chmod(auditDirectory, 0o700);
    await writeFile(hostFile, `${targets.join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (error) {
    activeAuditJob = null;
    throw error;
  }

  const job = {
    id,
    mode,
    status: 'running',
    startedAt: new Date().toISOString(),
    completedAt: null,
    exitCode: null,
    output: ''
  };
  auditJobs.set(id, job);

  const env = {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: process.env.HOME || appDirectory,
    USER: process.env.USER || '',
    LOGNAME: process.env.LOGNAME || '',
    SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK || '',
    LANG: 'C.UTF-8',
    HOSTS_FILE: hostFile,
    OUT_ROOT: auditDirectory,
    REPORTS_ROOT: auditDirectory,
    SSH_USER: 'scanlog',
    DAYS: String(logDays),
    COLLECT_BROWSER: '0',
    JOBS: '0', // Run collection and optional ClamAV scans on all selected PCs concurrently.
    EXCLUDE_IPS: '',
    CLAM_SCAN: mode === 'scan' ? '1' : '0',
    SCAN_DAYS: String(scanDays),
    AM_USER: 'AM',
    PM_USER: 'PM',
    ADMIN_USER: 'admin2025'
  };
  const child = spawn('bash', [auditScriptPath, mode], {
    cwd: appDirectory,
    env,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  const appendOutput = chunk => {
    job.output = `${job.output}${chunk.toString('utf8')}`.slice(-100_000);
  };
  child.stdout.on('data', appendOutput);
  child.stderr.on('data', appendOutput);
  child.stdin.on('error', error => {
    if (error.code !== 'EPIPE') appendOutput(`\nCould not send sudo password to audit script: ${error.message}`);
  });
  child.stdin.end(`${sudoPassword}\n`);
  sudoPassword = '';
  child.once('error', error => {
    job.status = 'failed';
    job.output = `${job.output}\nCould not start audit script: ${error.message}`.slice(-100_000);
  });
  child.once('close', async (code, signal) => {
    job.exitCode = code;
    job.status = code === 0 ? 'completed' : 'failed';
    job.completedAt = new Date().toISOString();
    if (signal) job.output = `${job.output}\nStopped by signal ${signal}.`.slice(-100_000);
    activeAuditJob = null;
    await unlink(hostFile).catch(error => {
      if (error.code !== 'ENOENT') console.error('Could not remove audit target list:', error);
    });
  });

  if (auditJobs.size > 20) {
    const oldestFinished = [...auditJobs.values()].find(entry => entry.status !== 'running');
    if (oldestFinished) auditJobs.delete(oldestFinished.id);
  }
  return job;
}

function execFileResult(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      if (error) {
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
}

async function auditCollectorPayload() {
  return execFileResult('bash', [auditScriptPath, 'payload'], {
    cwd: appDirectory,
    maxBuffer: 2_000_000,
    windowsHide: true,
    encoding: 'utf8'
  });
}

async function auditSshPublicKey() {
  const sshDirectory = join(process.env.HOME || appDirectory, '.ssh');
  const privateKeyPath = join(sshDirectory, 'id_ed25519');
  const publicKeyPath = `${privateKeyPath}.pub`;
  await mkdir(sshDirectory, { recursive: true, mode: 0o700 });
  await chmod(sshDirectory, 0o700);
  let privateKeyExists = true;
  try {
    await readFile(privateKeyPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    privateKeyExists = false;
  }
  let publicKey = '';
  try {
    publicKey = (await readFile(publicKeyPath, 'utf8')).trim();
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!privateKeyExists && !publicKey) {
    await execFileResult('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', privateKeyPath], {
      windowsHide: true,
      maxBuffer: 16_384
    });
    publicKey = (await readFile(publicKeyPath, 'utf8')).trim();
  } else if (!privateKeyExists || !publicKey) {
    throw new Error('The app SSH key pair is incomplete; repair ~/.ssh/id_ed25519 before provisioning');
  }
  if (!/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[^\s]+) [A-Za-z0-9+/=]+(?: .*)?$/.test(publicKey)) {
    throw new Error('The app SSH public key is invalid');
  }
  await chmod(privateKeyPath, 0o600);
  return publicKey;
}

function shellQuote(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

async function connectForProvision(ip, password) {
  if (!await checkSshPort(ip)) throw new Error('SSH port 22 did not respond');
  const hostKeys = await readSshHostKeys();
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) {
        client.end();
        reject(error);
      } else {
        resolve(client);
      }
    };
    const timeout = setTimeout(() => finish(new Error('SSH connection timed out')), 12_000);
    client.once('ready', () => finish());
    client.once('error', error => finish(new Error(
      /All configured authentication methods failed|authentication|permission denied/i.test(error.message)
        ? 'SSH password authentication for scanlog failed'
        : error.message
    )));
    client.connect({
      host: ip,
      port: 22,
      username: 'scanlog',
      password,
      agent: false,
      tryKeyboard: false,
      authHandler: ['password'],
      readyTimeout: 8_000,
      hostHash: 'sha256',
      hostVerifier: (hostHash, verify) => {
        const fingerprint = `SHA256:${Buffer.from(hostHash, 'hex').toString('base64').replace(/=+$/, '')}`;
        const existing = hostKeys[ip];
        if (existing) {
          const matches = existing === fingerprint;
          verify(matches);
          if (!matches) finish(new Error('SSH host key changed; verify it before provisioning'));
          return;
        }
        saveSshHostKey(ip, fingerprint).then(
          () => verify(true),
          error => {
            console.error(`Could not save SSH host key for ${ip}:`, error);
            verify(false);
            finish(new Error('Could not save SSH host key'));
          }
        );
      }
    });
  });
}

function runSshCommand(client, command, input = '') {
  return new Promise((resolve, reject) => {
    client.exec(command, (error, channel) => {
      if (error) {
        reject(error);
        return;
      }
      let stdout = '';
      let stderr = '';
      channel.on('data', chunk => { stdout += chunk.toString('utf8'); });
      channel.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
      channel.once('error', reject);
      channel.once('close', (code, signal) => {
        if (code !== 0) {
          reject(new Error((stderr || stdout || `Remote command failed (${signal || code})`).trim().slice(-2000)));
        } else {
          resolve(stdout.trim());
        }
      });
      if (input) channel.end(input);
      else channel.end();
    });
  });
}

function uploadSshFile(client, remotePath, contents) {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error);
        return;
      }
      sftp.writeFile(remotePath, contents, { mode: 0o600 }, writeError => {
        sftp.end();
        if (writeError) reject(writeError);
        else resolve();
      });
    });
  });
}

async function provisionAuditTarget(ip, sshPassword, sudoPassword, payload, publicKey) {
  const client = await connectForProvision(ip, sshPassword);
  try {
    await runSshCommand(client,
      `set -eu; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; if ! grep -qxF -- ${shellQuote(publicKey)} "$HOME/.ssh/authorized_keys"; then printf '%s\\n' ${shellQuote(publicKey)} >> "$HOME/.ssh/authorized_keys"; fi`
    );
    await uploadSshFile(client, '/tmp/audit-collect.new', payload);
    const sudoCommand = [
      'set -eu',
      'install -m 0750 -o root -g root /tmp/audit-collect.new /usr/local/sbin/audit-collect',
      'rm -f /tmp/audit-collect.new',
      `printf '%s ALL=(root) PASSWD: /usr/local/sbin/audit-collect\\n' scanlog > /etc/sudoers.d/audit-collect.tmp`,
      'chmod 0440 /etc/sudoers.d/audit-collect.tmp',
      'visudo -cf /etc/sudoers.d/audit-collect.tmp',
      'mv /etc/sudoers.d/audit-collect.tmp /etc/sudoers.d/audit-collect'
    ].join(' && ');
    await runSshCommand(client, `sudo -S -k -p '' -- sh -c ${shellQuote(sudoCommand)}`, `${sudoPassword}\n`);
  } finally {
    client.end();
  }
}

async function startProvisionJob(targets, sshPassword, sudoPassword) {
  if (activeAuditJob) throw new HttpError(409, 'An audit run is already in progress');
  const id = randomUUID();
  activeAuditJob = id;
  const job = {
    id,
    mode: 'setup',
    status: 'running',
    startedAt: new Date().toISOString(),
    completedAt: null,
    exitCode: null,
    output: 'Provisioning selected PCs from the app. No terminal prompts are required.\n'
  };
  auditJobs.set(id, job);
  if (auditJobs.size > 20) {
    const oldestFinished = [...auditJobs.values()].find(entry => entry.status !== 'running');
    if (oldestFinished) auditJobs.delete(oldestFinished.id);
  }
  void (async () => {
    let failed = false;
    try {
      const [payload, publicKey] = await Promise.all([auditCollectorPayload(), auditSshPublicKey()]);
      for (const ip of targets) {
        job.output += `>>> Configuring ${ip}...\n`;
        try {
          await provisionAuditTarget(ip, sshPassword, sudoPassword, payload, publicKey);
          job.output += `Setup complete: ${ip}\n`;
        } catch (error) {
          failed = true;
          job.output += `Setup failed: ${ip} (${error.message})\n`;
        }
        job.output = job.output.slice(-100_000);
      }
      job.output += failed ? 'Provisioning finished with errors.\n' : 'Provisioning completed successfully.\n';
      job.exitCode = failed ? 1 : 0;
      job.status = failed ? 'failed' : 'completed';
    } catch (error) {
      job.output += `Provisioning failed: ${error.message}\n`;
      job.exitCode = 1;
      job.status = 'failed';
    } finally {
      sshPassword = '';
      sudoPassword = '';
      job.completedAt = new Date().toISOString();
      activeAuditJob = null;
    }
  })();
  return job;
}

function scanSshHosts(subnet) {
  const target = validateScanSubnet(subnet);
  return new Promise((resolve, reject) => {
    execFile('nmap', ['-sT', '-n', '-p22', '--open', '-oG', '-', target], {
      timeout: 60_000,
      windowsHide: true,
      maxBuffer: 128_000
    }, (error, stdout, stderr) => {
      if (error?.code === 'ENOENT') {
        reject(new HttpError(503, 'Nmap is not installed on the app server'));
        return;
      }
      if (error?.killed) {
        reject(new HttpError(504, 'The Nmap scan timed out'));
        return;
      }
      if (error) {
        const detail = String(stderr).trim().split('\n')[0];
        reject(new HttpError(502, detail ? `Nmap scan failed: ${detail}` : 'Nmap scan failed'));
        return;
      }

      const hosts = new Set();
      for (const line of String(stdout).split(/\r?\n/)) {
        const match = line.match(/^Host:\s+(\S+).*Ports:.*\b22\/open\/tcp\b/);
        if (match && isIP(match[1]) === 4) hosts.add(match[1]);
      }
      resolve([...hosts].sort((left, right) => {
        const toNumber = ip => ip.split('.').reduce((value, octet) => value * 256 + Number(octet), 0);
        return toNumber(left) - toNumber(right);
      }));
    });
  });
}

function checkSshPort(ip) {
  return new Promise(resolve => {
    const socket = createConnection({ host: ip, port: 22 });
    let finished = false;
    const finish = reachable => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(1800);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function readSshHostKeys() {
  try {
    const contents = await readFile(sshHostKeysPath, 'utf8');
    const keys = JSON.parse(contents);
    if (!keys || typeof keys !== 'object' || Array.isArray(keys)) {
      throw new Error('Saved SSH host-key data is invalid');
    }
    return keys;
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

function saveSshHostKey(ip, fingerprint) {
  const write = sshHostKeyWrite.then(async () => {
    const keys = await readSshHostKeys();
    if (keys[ip] && keys[ip] !== fingerprint) {
      throw new Error('The SSH host key changed during connection');
    }
    if (keys[ip]) return;
    keys[ip] = fingerprint;
    await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
    const temporaryPath = `${sshHostKeysPath}.${randomUUID()}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(keys, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await rename(temporaryPath, sshHostKeysPath);
    await chmod(sshHostKeysPath, 0o600);
  });
  sshHostKeyWrite = write.catch(error => {
    console.error('Could not persist SSH host key:', error);
  });
  return write;
}

async function checkSsh(ip, password) {
  if (activeSshChecks.has(ip)) {
    throw new HttpError(409, 'An SSH test is already running for this host');
  }
  activeSshChecks.add(ip);
  try {
    return await connectSshWithPassword(ip, password);
  } finally {
    activeSshChecks.delete(ip);
  }
}

async function connectSshWithPassword(ip, password) {
  if (!await checkSshPort(ip)) {
    return {
      status: 'port-unreachable',
      authenticated: false,
      message: 'SSH port 22 did not respond; it may be closed or filtered'
    };
  }

  const hostKeys = await readSshHostKeys();
  let rejectedHostKey = false;
  let finished = false;

  return new Promise(resolve => {
    const client = new Client();
    const finish = result => {
      if (finished) return;
      finished = true;
      client.end();
      resolve(result);
    };
    const timeout = setTimeout(() => finish({
      status: 'ssh-timeout',
      authenticated: false,
      message: 'SSH did not complete within the time limit'
    }), 12_000);
    const complete = result => {
      clearTimeout(timeout);
      finish(result);
    };

    client.once('ready', () => complete({
          status: 'authenticated',
          authenticated: true,
          message: 'SSH password authentication succeeded for scanlog'
        }));
    client.once('error', error => {
      if (rejectedHostKey) {
        complete({
          status: 'host-key',
          authenticated: false,
          message: 'SSH host key was rejected; verify it has not changed before reconnecting'
        });
      } else if (/All configured authentication methods failed|authentication|permission denied/i.test(error.message)) {
        complete({
          status: 'auth-failed',
          authenticated: false,
          message: 'SSH reached the host, but password authentication for scanlog was denied'
        });
      } else {
        complete({
          status: 'ssh-error',
          authenticated: false,
          message: 'SSH could not complete; check the host SSH configuration'
        });
      }
    });
    client.connect({
      host: ip,
      port: 22,
      username: 'scanlog',
      password,
      agent: false,
      tryKeyboard: false,
      authHandler: ['password'],
      readyTimeout: 8_000,
      hostHash: 'sha256',
      hostVerifier: (hostHash, verify) => {
        const fingerprint = `SHA256:${Buffer.from(hostHash, 'hex').toString('base64').replace(/=+$/, '')}`;
        const existing = hostKeys[ip];
        if (existing) {
          const matches = existing === fingerprint;
          if (!matches) rejectedHostKey = true;
          verify(matches);
          return;
        }
        saveSshHostKey(ip, fingerprint).then(
          () => verify(true),
          error => {
            console.error(`Could not save SSH host key for ${ip}:`, error);
            verify(false);
          }
        );
      }
    });
  });
}

async function readItems() {
  try {
    const contents = await readFile(dataPath, 'utf8');
    const items = JSON.parse(contents);
    if (!Array.isArray(items)) throw new Error('Stored floor plan is not an array');
    return items;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function readRequestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) throw new HttpError(413, 'Request body is too large');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Request body must be valid JSON');
  }
}

function validateItems(value) {
  if (!Array.isArray(value) || value.length > 1000) {
    throw new HttpError(400, 'Items must be an array containing no more than 1000 entries');
  }

  const ids = new Set();
  return value.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new HttpError(400, 'Each item must be an object');
    }
    const { id, type, x, y } = item;
    if (typeof id !== 'string' || !/^[\w-]{1,64}$/.test(id) || ids.has(id)) {
      throw new HttpError(400, 'Each item must have a unique, valid id');
    }
    if (!['room', 'desk', 'table', 'pc', 'router'].includes(type)) {
      throw new HttpError(400, 'Item type is invalid');
    }
    if (![x, y].every(Number.isFinite) || x < 0 || x > 1200 || y < 0 || y > 1400) {
      throw new HttpError(400, 'Item position is invalid');
    }
    ids.add(id);

    const result = { id, type, x, y };
    if (type === 'room' || type === 'desk' || type === 'table') {
      const minSize = type === 'room' ? 80 : 40;
      if (![item.w, item.h].every(Number.isFinite) ||
          item.w < minSize || item.h < minSize || item.w > 2400 || item.h > 2400) {
        throw new HttpError(400, 'Item dimensions are invalid');
      }
      result.w = item.w;
      result.h = item.h;
    }
    if (type === 'room' || type === 'pc' || type === 'router') {
      if (item.name !== undefined && (typeof item.name !== 'string' || item.name.length > 30)) {
        throw new HttpError(400, 'Item name is invalid');
      }
      if (item.name !== undefined) result.name = item.name;
    }
    if (type === 'room') {
      if (item.name === undefined) result.name = '';
    } else {
      if (item.r !== undefined && !Number.isFinite(item.r)) {
        throw new HttpError(400, 'Item angle is invalid');
      }
      result.r = item.r || 0;
    }
    if (type === 'desk' && item.t !== undefined) {
      if (!Number.isFinite(item.t) || item.t < 16 || item.t > 600) {
        throw new HttpError(400, 'Desk arm thickness is invalid');
      }
      result.t = item.t;
    }
    if (type === 'pc' || type === 'router') {
      if (item.ip !== undefined && (typeof item.ip !== 'string' || item.ip.length > 45)) {
        throw new HttpError(400, 'Device IP address is invalid');
      }
      if (item.ip !== undefined) result.ip = item.ip;
      if (type === 'router' && item.model !== undefined &&
          (typeof item.model !== 'string' || item.model.length > 30)) {
        throw new HttpError(400, 'Router model is invalid');
      }
      if (type === 'router' && item.model !== undefined) result.model = item.model;
    }
    if (type === 'pc') {
      for (const [field, maxLength] of [['distro', 30]]) {
        if (item[field] !== undefined &&
            (typeof item[field] !== 'string' || item[field].length > maxLength)) {
          throw new HttpError(400, `PC ${field} is invalid`);
        }
        if (item[field] !== undefined) result[field] = item[field];
      }
      if (item.os !== undefined && !['ubuntu', 'other'].includes(item.os)) {
        throw new HttpError(400, 'PC operating system is invalid');
      }
      result.os = item.os || 'ubuntu';
    }
    return result;
  });
}

async function writeItems(items) {
  await mkdir(dataDirectory, { recursive: true });
  const temporaryPath = `${dataPath}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(items, null, 2)}\n`, 'utf8');
  await rename(temporaryPath, dataPath);
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (url.pathname === '/api/items' && request.method === 'GET') {
      const items = await readItems();
      sendJson(response, 200, { items: items || [], initialized: items !== null });
      return;
    }
    if (url.pathname === '/api/items' && request.method === 'PUT') {
      const items = validateItems(await readRequestBody(request));
      await writeItems(items);
      sendJson(response, 200, { ok: true });
      return;
    }
    if (url.pathname === '/api/connectivity' && request.method === 'POST') {
      const body = await readRequestBody(request);
      if (!body || typeof body !== 'object' || Array.isArray(body) ||
          typeof body.ip !== 'string' || isIP(body.ip) === 0) {
        throw new HttpError(400, 'Enter a valid IPv4 or IPv6 address');
      }
      const result = await pingAddress(body.ip);
      sendJson(response, 200, { ...result, checkedAt: new Date().toISOString() });
      return;
    }
    if (url.pathname === '/api/ssh-check' && request.method === 'POST') {
      if (!isLoopbackRequest(request) || !isSameOriginRequest(request)) {
        throw new HttpError(403, 'SSH checks can only be requested from this machine');
      }
      const body = await readRequestBody(request);
      if (!body || typeof body !== 'object' || Array.isArray(body) ||
          typeof body.ip !== 'string' || isIP(body.ip) === 0 ||
          typeof body.password !== 'string' || body.password.length === 0 || body.password.length > 1024) {
        throw new HttpError(400, 'Enter a valid IPv4 or IPv6 address and a password no longer than 1024 characters');
      }
      const result = await checkSsh(body.ip, body.password);
      sendJson(response, 200, { ...result, checkedAt: new Date().toISOString() });
      return;
    }
    if (url.pathname === '/api/ssh-scan' && request.method === 'POST') {
      const body = await readRequestBody(request);
      if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.subnet !== 'string') {
        throw new HttpError(400, 'Provide a valid private IPv4 subnet');
      }
      const hosts = await scanSshHosts(body.subnet);
      sendJson(response, 200, {
        subnet: body.subnet,
        hosts: hosts.map(ip => ({ ip })),
        checkedAt: new Date().toISOString()
      });
      return;
    }
    if (url.pathname === '/api/audit-runs' && request.method === 'POST') {
      if (!isLoopbackRequest(request) || !isSameOriginRequest(request)) {
        throw new HttpError(403, 'Audit runs can only be started from this machine');
      }
      if (process.platform !== 'linux') {
        throw new HttpError(503, 'The audit collector requires a Linux app server');
      }
      const body = await readRequestBody(request);
      if (!body || typeof body !== 'object' || Array.isArray(body) ||
          !['collect', 'scan', 'setup'].includes(body.mode) || body.confirmed !== true ||
          !Number.isInteger(body.logDays) || body.logDays < 1 || body.logDays > 365 ||
          !Number.isInteger(body.scanDays) || body.scanDays < 0 || body.scanDays > 365) {
        throw new HttpError(400, 'Confirm the audit action and provide a valid mode and scan window');
      }
      if (body.mode === 'setup' &&
          (typeof body.sshPassword !== 'string' || body.sshPassword.length === 0 ||
           body.sshPassword.length > 1024 || /[\r\n\0]/.test(body.sshPassword))) {
        throw new HttpError(400, 'Enter a valid SSH password (maximum 1024 characters)');
      }
      if (typeof body.sudoPassword !== 'string' || body.sudoPassword.length === 0 ||
          body.sudoPassword.length > 1024 || /[\r\n\0]/.test(body.sudoPassword)) {
        throw new HttpError(400, 'Enter a valid sudo password (maximum 1024 characters)');
      }
      const targets = validateAuditTargets(body.targets);
      const job = body.mode === 'setup'
        ? await startProvisionJob(targets, body.sshPassword, body.sudoPassword)
        : await startAuditJob(body.mode, targets, body.logDays, body.scanDays, body.sudoPassword);
      body.sshPassword = '';
      body.sudoPassword = '';
      sendJson(response, 202, {
        id: job.id,
        mode: job.mode,
        status: job.status,
        startedAt: job.startedAt
      });
      return;
    }
    if (url.pathname === '/api/audit-tracking-sheet.csv' && request.method === 'GET') {
      if (!isLoopbackRequest(request) || !isSameOriginRequest(request)) {
        throw new HttpError(403, 'Tracking-sheet exports can only be downloaded from this machine');
      }
      const month = new Intl.DateTimeFormat('en-US', { month: 'long' }).format(new Date());
      const filename = `scan_log_${month}.csv`;
      const path = join(auditDirectory, `${month} Scan Logs`, filename);
      let contents;
      try {
        contents = await readFile(path);
      } catch (error) {
        if (error.code === 'ENOENT') {
          throw new HttpError(404, 'No tracking-sheet CSV exists yet. Run an audit collection first.');
        }
        throw error;
      }
      response.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      });
      response.end(contents);
      return;
    }
    const auditJobMatch = url.pathname.match(/^\/api\/audit-runs\/([0-9a-f-]{36})$/i);
    if (auditJobMatch && request.method === 'GET') {
      if (!isLoopbackRequest(request) || !isSameOriginRequest(request)) {
        throw new HttpError(403, 'Audit results can only be viewed from this machine');
      }
      const job = auditJobs.get(auditJobMatch[1]);
      if (!job) throw new HttpError(404, 'Audit run was not found');
      sendJson(response, 200, job);
      return;
    }
    if (url.pathname === '/' && request.method === 'GET') {
      const html = await readFile(pagePath);
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      response.end(html);
      return;
    }
    if (url.pathname === '/styles.css' && request.method === 'GET') {
      const stylesheet = await readFile(stylesheetPath);
      response.writeHead(200, {
        'Content-Type': 'text/css; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      });
      response.end(stylesheet);
      return;
    }
    sendJson(response, 404, { error: 'Not found' });
  } catch (error) {
    if (error instanceof HttpError) {
      sendJson(response, error.status, { error: error.message });
      return;
    }
    console.error('Request failed:', error);
    sendJson(response, 500, { error: 'Internal server error' });
  }
});

server.listen(port, host, () => {
  console.log(`Office floor plan is available at http://${host}:${port}`);
});
