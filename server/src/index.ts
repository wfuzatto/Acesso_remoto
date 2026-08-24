import { createServer } from 'node:http';
import { createHmac, randomInt, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';

type Role = 'host' | 'viewer';
type SessionState = 'pending' | 'challenge' | 'authorized' | 'closed';

type Client = {
  ws: WebSocket;
  role?: Role;
  deviceId?: string;
  accessId?: string;
  platform?: string;
  name?: string;
  sessionIds: Set<string>;
};

type Session = {
  id: string;
  host: Client;
  viewer: Client;
  state: SessionState;
  unattended: boolean;
  createdAt: number;
};

type DeviceStore = { devices: Record<string, { accessId: string; createdAt: number }> };

const PORT = Number(process.env.PORT ?? 8080);
const DATA_DIR = process.env.DATA_DIR ?? './data';
const STORE_PATH = join(DATA_DIR, 'devices.json');
const STUN_URL = process.env.STUN_URL ?? 'stun:stun.l.google.com:19302';
const TURN_URL = process.env.TURN_URL ?? '';
const TURN_TLS_URL = process.env.TURN_TLS_URL ?? '';
const TURN_SECRET = process.env.TURN_SECRET ?? '';

mkdirSync(DATA_DIR, { recursive: true });

function loadStore(): DeviceStore {
  try {
    const parsed = JSON.parse(readFileSync(STORE_PATH, 'utf8')) as DeviceStore;
    if (parsed?.devices) return parsed;
  } catch { }
  return { devices: {} };
}

const store = loadStore();
const clients = new Set<Client>();
const hostsByAccessId = new Map<string, Client>();
const sessions = new Map<string, Session>();

function saveStore() {
  writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
}

function allocateAccessId(deviceId: string): string {
  const existing = store.devices[deviceId]?.accessId;
  if (existing) return existing;

  const used = new Set(Object.values(store.devices).map(d => d.accessId));
  let id: string;
  do id = String(randomInt(100_000_000, 1_000_000_000)); while (used.has(id));
  store.devices[deviceId] = { accessId: id, createdAt: Date.now() };
  saveStore();
  return id;
}

function makeIceServers(clientId: string) {
  const servers: Array<Record<string, unknown>> = [{ urls: [STUN_URL] }];
  if (TURN_SECRET && (TURN_URL || TURN_TLS_URL)) {
    const expires = Math.floor(Date.now() / 1000) + 60 * 60;
    const username = `${expires}:${clientId.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 80)}`;
    const credential = createHmac('sha1', TURN_SECRET).update(username).digest('base64');
    const urls = [TURN_URL, TURN_TLS_URL].filter(Boolean);
    servers.push({ urls, username, credential, credentialType: 'password' });
  }
  return servers;
}

const server = createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify({ ok: true, hosts: hostsByAccessId.size, sessions: sessions.size, persistentDevices: Object.keys(store.devices).length }));
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server, maxPayload: 16 * 1024 * 1024 });

function send(client: Client, message: unknown) {
  if (client.ws.readyState === WebSocket.OPEN) client.ws.send(JSON.stringify(message));
}

function closeSession(session: Session, reason = 'closed') {
  if (session.state === 'closed') return;
  session.state = 'closed';
  sessions.delete(session.id);
  session.host.sessionIds.delete(session.id);
  session.viewer.sessionIds.delete(session.id);
  send(session.host, { type: 'session.closed', sessionId: session.id, reason });
  send(session.viewer, { type: 'session.closed', sessionId: session.id, reason });
}

function parseJson(data: Buffer): any | null {
  try { return JSON.parse(data.toString('utf8')); } catch { return null; }
}

function peerOf(session: Session, client: Client) {
  if (session.host === client) return session.viewer;
  if (session.viewer === client) return session.host;
  return null;
}

wss.on('connection', (ws) => {
  const client: Client = { ws, sessionIds: new Set() };
  clients.add(client);

  ws.on('message', (raw, isBinary) => {
    if (isBinary) {
      // Legacy JPEG/WebSocket fallback. WebRTC-capable clients should use P2P/TURN instead.
      const buf = Buffer.from(raw as Buffer);
      if (buf.length <= 36) return;
      const sessionId = buf.subarray(0, 36).toString('ascii');
      const session = sessions.get(sessionId);
      if (!session || session.state !== 'authorized' || session.host !== client) return;
      if (session.viewer.ws.readyState === WebSocket.OPEN) session.viewer.ws.send(buf, { binary: true });
      return;
    }

    const msg = parseJson(Buffer.from(raw as Buffer));
    if (!msg || typeof msg.type !== 'string') return;

    if (msg.type === 'register.host') {
      if (typeof msg.deviceId !== 'string' || msg.deviceId.length < 8) return;
      client.role = 'host';
      client.deviceId = msg.deviceId;
      client.platform = String(msg.platform ?? 'windows');
      client.name = String(msg.name ?? 'Windows PC').slice(0, 80);
      const accessId = allocateAccessId(msg.deviceId);
      client.accessId = accessId;
      const previous = hostsByAccessId.get(accessId);
      if (previous && previous !== client) previous.ws.close(4001, 'device-reconnected');
      hostsByAccessId.set(accessId, client);
      send(client, { type: 'registered', accessId, iceServers: makeIceServers(msg.deviceId) });
      return;
    }

    if (msg.type === 'register.viewer') {
      client.role = 'viewer';
      client.platform = String(msg.platform ?? 'unknown');
      client.name = String(msg.name ?? 'Viewer').slice(0, 80);
      const viewerId = typeof msg.deviceId === 'string' ? msg.deviceId : randomUUID();
      send(client, { type: 'viewer.registered', iceServers: makeIceServers(viewerId) });
      return;
    }

    if (msg.type === 'connection.request' && client.role === 'viewer') {
      const accessId = String(msg.accessId ?? '').replace(/\D/g, '');
      const host = hostsByAccessId.get(accessId);
      if (!host || host.ws.readyState !== WebSocket.OPEN) return send(client, { type: 'connection.error', code: 'HOST_OFFLINE' });
      if (host.sessionIds.size >= 1) return send(client, { type: 'connection.error', code: 'HOST_BUSY' });

      const session: Session = { id: randomUUID(), host, viewer: client, state: 'pending', unattended: Boolean(msg.unattended), createdAt: Date.now() };
      sessions.set(session.id, session);
      host.sessionIds.add(session.id);
      client.sessionIds.add(session.id);
      send(host, { type: 'connection.request', sessionId: session.id, unattended: session.unattended, viewer: { name: client.name, platform: client.platform } });
      send(client, { type: 'connection.pending', sessionId: session.id });
      return;
    }

    const sessionId = String(msg.sessionId ?? '');
    const session = sessions.get(sessionId);
    if (!session || !client.sessionIds.has(sessionId)) return;

    if (msg.type === 'connection.accept' && session.host === client && !session.unattended) {
      session.state = 'authorized';
      send(session.viewer, { type: 'connection.accepted', sessionId, transport: 'webrtc-preferred' });
      send(session.host, { type: 'session.authorized', sessionId, transport: 'webrtc-preferred' });
      return;
    }

    if (msg.type === 'connection.reject' && session.host === client) return closeSession(session, 'rejected');

    if (msg.type === 'auth.challenge' && session.host === client && session.unattended && session.state === 'pending') {
      session.state = 'challenge';
      send(session.viewer, { type: 'auth.challenge', sessionId, salt: msg.salt, iterations: msg.iterations, nonce: msg.nonce });
      return;
    }

    if (msg.type === 'auth.response' && session.viewer === client && session.state === 'challenge') {
      send(session.host, { type: 'auth.response', sessionId, proof: msg.proof });
      return;
    }

    if (msg.type === 'auth.result' && session.host === client && session.state === 'challenge') {
      if (msg.ok === true) {
        session.state = 'authorized';
        send(session.viewer, { type: 'connection.accepted', sessionId, transport: 'webrtc-preferred' });
        send(session.host, { type: 'session.authorized', sessionId, transport: 'webrtc-preferred' });
      } else {
        send(session.viewer, { type: 'connection.error', code: 'AUTH_FAILED' });
        closeSession(session, 'auth_failed');
      }
      return;
    }

    // WebRTC SDP/ICE is relayed only after explicit authorization.
    if (session.state === 'authorized' && ['rtc.offer', 'rtc.answer', 'rtc.ice', 'rtc.restart'].includes(msg.type)) {
      const peer = peerOf(session, client);
      if (peer) send(peer, { ...msg, sessionId });
      return;
    }

    // Legacy input relay remains as fallback until both clients use WebRTC data channels.
    if (msg.type === 'input' && session.viewer === client && session.state === 'authorized') {
      send(session.host, { ...msg, type: 'input', sessionId });
      return;
    }

    if (msg.type === 'session.close') closeSession(session, 'peer_closed');
  });

  ws.on('close', () => {
    clients.delete(client);
    if (client.role === 'host' && client.accessId && hostsByAccessId.get(client.accessId) === client) hostsByAccessId.delete(client.accessId);
    for (const id of [...client.sessionIds]) {
      const session = sessions.get(id);
      if (session) closeSession(session, 'peer_disconnected');
    }
  });
});

setInterval(() => {
  const now = Date.now();
  for (const session of sessions.values()) {
    if (session.state !== 'authorized' && now - session.createdAt > 60_000) closeSession(session, 'timeout');
  }
}, 10_000).unref();

server.listen(PORT, '0.0.0.0', () => console.log(`Acesso Remoto signaling listening on :${PORT}`));
