import { defineConfig, type Plugin } from 'vite';
import fs from 'fs';
import path from 'path';
import { mtp } from 'mtp/vite';

const exampleDir = path.resolve(__dirname, '..');
const devCertDir = path.join(exampleDir, 'dev-cert');
const certPath = process.env.MTP_DEV_CERT ?? path.join(devCertDir, 'cert.pem');
const keyPath = process.env.MTP_DEV_KEY ?? path.join(devCertDir, 'key.pem');

const hasDevCert = fs.existsSync(certPath) && fs.existsSync(keyPath);

const devFiles: Record<string, string> = {
  '/host_public_key_bundle.hex': path.join(exampleDir, 'host_public_key_bundle.hex'),
  '/mtp_dev_cert_hash.txt': path.join(devCertDir, 'sha256.txt'),
};

function devFileServe(): Plugin {
  return {
    name: 'dev-file-serve',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const target = devFiles[req.url?.split('?')[0] ?? ''];
        if (!target) return next();

        fs.readFile(target, (err, data) => {
          if (err) return next();
          res.setHeader('Content-Type', 'text/plain');
          res.setHeader('Cache-Control', 'no-store');
          res.end(data);
        });
      });
    },
  };
}

export default defineConfig({
  plugins: [mtp({ typeMaps: '../../example/type-maps.yaml' }), devFileServe()],
  server: {
    https: hasDevCert
      ? {
          cert: fs.readFileSync(certPath),
          key: fs.readFileSync(keyPath),
        }
      : undefined,
  },
});
