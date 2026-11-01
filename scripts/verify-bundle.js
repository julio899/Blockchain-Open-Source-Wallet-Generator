import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bundle = path.join(root, "dist/wallet.bundle.js");

if (!fs.existsSync(bundle)) {
  console.error("No existe dist/wallet.bundle.js. Ejecute `npm run build:web`.");
  process.exit(1);
}

const code = fs.readFileSync(bundle, "utf8");

/**
 * El bundle del navegador tiene que poder ejecutarse sin red y sin acceso a
 * APIs de Node. Si alguna de estas cadenas aparece, algo se coló en la cadena
 * de dependencias y hay que revisarlo antes de publicar.
 */
const PROHIBIDO = [
  ["node:", "import de módulos de Node"],
  ["http://", "URL de red"],
  ["https://", "URL de red"],
  ["innerHTML", "inyección de markup"],
  ["eval(", "código dinámico"],
  ["new Function", "código dinámico"],
  ["document.write", "escritura de documento"],
  ["Math.random", "aleatoriedad no criptográfica"],
];

const fallos = PROHIBIDO.filter(([needle]) => code.includes(needle)).map(
  ([needle, motivo]) => `  - ${needle} (${motivo})`
);

const sha256 = createHash("sha256").update(code).digest("hex");
console.log(`dist/wallet.bundle.js  ${(code.length / 1024).toFixed(1)} KiB`);
console.log(`sha256: ${sha256}`);

if (fallos.length > 0) {
  console.error("\nEl bundle contiene patrones prohibidos:");
  console.error(fallos.join("\n"));
  process.exit(1);
}

console.log("Bundle limpio: sin red, sin APIs de Node, sin Math.random.");
