import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createGateway } from './server.js';

function port(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!/^[1-9][0-9]{0,4}$/.test(value)) throw new Error('Invalid port');
  const parsed = Number(value);
  if (parsed > 65535) throw new Error('Invalid port');
  return parsed;
}

const staticDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../ui');
const server = createGateway({ upstreamPort: port(process.env.XCLI_CORE_PORT, 18080), staticDir });
server.listen(port(process.env.XCLI_WEB_PORT, 18081), '127.0.0.1', () => process.stdout.write('XCLI Web 接入已启动（回环地址）\n'));
