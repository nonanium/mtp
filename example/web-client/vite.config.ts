import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';
import { mtp } from 'mtp/vite';

const devCertDir = path.resolve(__dirname, '../dev-cert');
const certPath = process.env.MTP_DEV_CERT ?? path.join(devCertDir, 'cert.pem');
const keyPath = process.env.MTP_DEV_KEY ?? path.join(devCertDir, 'key.pem');

const hasDevCert = fs.existsSync(certPath) && fs.existsSync(keyPath);

export default defineConfig({
  plugins: [mtp({ typeMaps: '../../example/type-maps.yaml' })],
  server: {
    https: hasDevCert
      ? {
          cert: fs.readFileSync(certPath),
          key: fs.readFileSync(keyPath),
        }
      : undefined,
  },
});
