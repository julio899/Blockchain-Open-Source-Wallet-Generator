#!/usr/bin/env node
import qrcode from "qrcode-terminal";
import { randomPrivateKey } from "../lib/random.js";
import { privateKeyToWallet } from "../lib/wallet.js";
import { generateMnemonicWallet, ETHEREUM_PATH } from "../lib/mnemonic.js";

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(`Uso: node src/cli/01-generar-wallet.js [opciones]

Genera una wallet Ethereum y la muestra en la terminal. No guarda nada.

Opciones:
  --mnemonic   Genera un mnemonic BIP-39 de 24 palabras y deriva ${ETHEREUM_PATH}
  --qr-key     Muestra también el QR de la clave privada (por defecto solo el QR
               de la dirección: un QR de la clave privada se puede fotografiar)
  -h, --help   Esta ayuda`);
  process.exit(0);
}

const useMnemonic = args.has("--mnemonic");
const showKeyQR = args.has("--qr-key");

const wallet = useMnemonic
  ? generateMnemonicWallet()
  : privateKeyToWallet(randomPrivateKey());

console.log("");
if (useMnemonic) {
  console.log("Mnemonic BIP-39 (guárdelo offline, es el respaldo de la wallet):");
  console.log(`  ${wallet.mnemonic}`);
  console.log("");
  console.log(`Ruta de derivación: ${ETHEREUM_PATH}`);
}
console.log(`Dirección : ${wallet.address}`);
console.log(`Clave priv: ${wallet.privateKey}`);
console.log("");

qrcode.generate(wallet.address, { small: true }, (qr) => {
  console.log("\tDirección");
  console.log(qr);
});

if (showKeyQR) {
  qrcode.generate(wallet.privateKey, { small: true }, (qr) => {
    console.log("\tClave privada (no fotografiar ni compartir)");
    console.log(qr);
  });
}
