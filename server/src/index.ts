import { createServer } from 'node:http';
import { randomInt, randomUUID } from 'node:crypto';
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

const PORT = Number(process.env.PORT ?? 8080);
const clients = new Set<Client>();
const hostsByAccessId = new Map<string, Client>();
const accessIdByDevice = new Map<string, string>();
const sessions = new Map<string, Session>();

const server = createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, hosts: hostsByAccessId.size, sessions: sessions.size }));
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server, maxPayload: 12 * 1024 * 1024 });

function send(client: Client, message: unknown) {
  if (client.ws.readyState === WebSocket.OPEN) {
    client.ws.send(JSON.stringify(message));
  }
}

function allocateAccessId(deviceId: string): string {
  const existing = accessIdByDevice.get(deviceId);
  if (existing) return existing;

  let id: string;
  do {
    id = String(randomInt(100_000_000, 1_000_000_000));
  } while (hostsByAccessId.has(id) || [...accessIdByDevice.values()].includes(id));

  accessIdByDevice.set(deviceId, id);
  return id;
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

wss.on('connection', (ws) => {
  const client: Client = { ws, sessionIds: new Set() };
  clients.add(client);

  ws.on('message', (raw, isBinary) => {
    if (isBinary) {
      // Binary packet format: 36-byte ASCII session UUID + payload.
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
      hostsByAccessId.set(accessId, client);
      send(client, { type: 'registered', accessId });
      return;
    }

    if (msg.type === 'register.viewer') {
      client.role = 'viewer';
      client.platform = String(msg.platform ?? 'unknown');
      client.name = String(msg.name ?? 'Viewer').slice(0, 80);
      send(client, { type: 'viewer.registered' });
      return;
    }

    if (msg.type === 'connection.request' && client.role === 'viewer') {
      const accessId = String(msg.accessId ?? '').replace(/\D/g, '');
      const host = hostsByAccessId.get(accessId);
      if (!host || host.ws.readyState !== WebSocket.OPEN) {
        send(client, { type: 'connection.error', code: 'HOST_OFFLINE' });
        return;
      }
      if (host.sessionIds.size >= 1) {
        send(client, { type: 'connection.error', code: 'HOST_BUSY' });
        return;
      }

      const session: Session = {
        id: randomUUID(),
        host,
        viewer: client,
        state: 'pending',
        unattended: Boolean(msg.unattended),
        createdAt: Date.now()
      };
      sessions.set(session.id, session);
      host.sessionIds.add(session.id);
      client.sessionIds.add(session.id);

      send(host, {
        type: 'connection.request',
        sessionId: session.id,
        unattended: session.unattended,
        viewer: { name: client.name, platform: client.platform }
      });
      send(client, { type: 'connection.pending', sessionId: session.id });
      return;
    }

    const sessionId = String(msg.sessionId ?? '');
    const session = sessions.get(sessionId);
    if (!session || !client.sessionIds.has(sessionId)) return;

    if (msg.type === 'connection.accept' && session.host === client && !session.unattended) {
      session.state = 'authorized';
      send(session.viewer, { type: 'connection.accepted', sessionId });
      send(session.host, { type: 'session.authorized', sessionId });
      return;
    }

    if (msg.type === 'connection.reject' && session.host === client) {
      closeSession(session, 'rejected');
      return;
    }

    // The relay only forwards unattended challenge material. Verification is local to the host.
    if (msg.type === 'auth.challenge' && session.host === client && session.unattended && session.state === 'pending') {
      session.state = 'challenge';
      send(session.viewer, {
        type: 'auth.challenge', sessionId,
        salt: msg.salt, iterations: msg.iterations, nonce: msg.nonce
      });
      return;
    }

    if (msg.type === 'auth.response' && session.viewer === client && session.state === 'challenge') {
      send(session.host, { type: 'auth.response', sessionId, proof: msg.proof });
      return;
    }

    if (msg.type === 'auth.result' && session.host === client && session.state === 'challenge') {
      if (msg.ok === true) {
        session.state = 'authorized';
        send(session.viewer, { type: 'connection.accepted', sessionId });
        send(session.host, { type: 'session.authorized', sessionId });
      } else {
        send(session.viewer, { type: 'connection.error', code: 'AUTH_FAILED' });
        closeSession(session, 'auth_failed');
      }
      return;
    }

    if (msg.type === 'input' && session.viewer === client && session.state === 'authorized') {
      // Only explicitly authorized sessions can inject input.
      send(session.host, { ...msg, type: 'input', sessionId });
      return;
    }

    if (msg.type === 'session.close') {
      closeSession(session, 'peer_closed');
    }
  });

  ws.on('close', () => {
    clients.delete(client);
    if (client.role === 'host' && client.accessId && hostsByAccessId.get(client.accessId) === client) {
      hostsByAccessId.delete(client.accessId);
    }
    for (const id of [...client.sessionIds]) {
      const session = sessions.get(id);
      if (session) closeSession(session, 'peer_disconnected');
    }
  });
});

setInterval(() => {
  const now = Date.now();
  for (const session of sessions.values()) {
    if (session.state !== 'authorized' && now - session.createdAt > 60_000) {
      closeSession(session, 'timeout');
    }
  }
}, 10_000).unref();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Acesso Remoto relay listening on :${PORT}`);
});
