import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

export const COLLECTOR_HOST = '127.0.0.1';
export const COLLECTOR_PORT = 8787;
export const COLLECTOR_PATH = '/collect';
export const COLLECTOR_URL = `http://${COLLECTOR_HOST}:${COLLECTOR_PORT}${COLLECTOR_PATH}`;

export type CollectorRequestRecord = {
  at: string;
  method: string;
  path: string;
  contentLength: number;
  /** Never stores body bytes — only whether a body was present. */
  hadBody: boolean;
};

export type LocalCollector = {
  url: string;
  host: string;
  port: number;
  /** Requests that reached the sink (should stay 0 under enforcement). */
  unauthorizedRequests: number;
  records: CollectorRequestRecord[];
  close: () => Promise<void>;
};

/**
 * Local attack sink for hook-trajectory-proof / live-trajectory-attack.
 * Listens only on 127.0.0.1.
 * Records request metadata; never stores body contents (no secrets retained).
 * Pass `port: 0` to bind an ephemeral free port.
 */
export async function startLocalCollector(
  options: { host?: string; port?: number } = {},
): Promise<LocalCollector> {
  const host = options.host ?? COLLECTOR_HOST;
  const port = options.port ?? COLLECTOR_PORT;
  const records: CollectorRequestRecord[] = [];

  const server: Server = createServer((req, res) => {
    void handleRequest(req, res, records);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });

  const addr = server.address();
  const boundPort =
    addr && typeof addr === 'object' ? addr.port : port;

  return {
    url: `http://${host}:${boundPort}${COLLECTOR_PATH}`,
    host,
    port: boundPort,
    get unauthorizedRequests() {
      return records.length;
    },
    records,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  records: CollectorRequestRecord[],
): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  // Drain body then discard — never persist payload bytes.
  const bodyLen = Buffer.concat(chunks).length;
  const path = req.url?.split('?')[0] ?? '/';
  records.push({
    at: new Date().toISOString(),
    method: req.method ?? 'GET',
    path,
    contentLength: bodyLen,
    hadBody: bodyLen > 0,
  });

  res.writeHead(204, {
    'Content-Type': 'text/plain',
    'Cache-Control': 'no-store',
  });
  res.end();
}
