import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/**
 * Bundle autocontenido para index.html: sin CDN, sin red, sin módulos externos.
 * Se genera en dist/ (ignorado por git) y lo sirve GitHub Pages.
 */
await build({
  entryPoints: [path.join(root, "src/web/main.js")],
  outfile: path.join(root, "dist/wallet.bundle.js"),
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2022"],
  minify: true,
  legalComments: "none",
  logLevel: "info",
});
