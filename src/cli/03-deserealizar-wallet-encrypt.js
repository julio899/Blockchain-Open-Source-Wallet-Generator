#!/usr/bin/env node
import qrcode from "qrcode-terminal";
import { privateKeyToWallet, normalizeAddress } from "../lib/wallet.js";
import { ask, askSecret, closePrompt } from "../lib/prompt.js";
import { decryptV3, inspectKeystore } from "../lib/keystore.js";
import { readKeystore } from "../lib/storage.js";

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(`Uso: node src/cli/03-deserealizar-wallet-encrypt.js [--qr-key]

Lee wallets/<dirección>-encrypt.json, lo descifra con la frase pedida por
terminal (sin echo) y muestra la clave privada.

Opciones:
  --qr-key     Muestra también el QR de la clave privada
  -h, --help   Esta ayuda`);
  process.exit(0);
}

const showKeyQR = args.has("--qr-key");

try {
  const addressInput = await ask("Dirección de la wallet a desencriptar (0x…): ");
  const address = normalizeAddress(addressInput);

  const passphrase = await askSecret("Frase de desencriptado: ");

  const { file, keystore } = readKeystore(address);

  const info = inspectKeystore(keystore);
  if (info.weak) {
    console.warn(
      "\nAviso: este keystore usa parámetros débiles (anteriores a la versión 2).\n" +
        "Cualquiera que tenga el archivo puede atacarlo con fuerza bruta mucho más rápido.\n" +
        "Recomendación: muévalo con `npm run recifrar` y valore migrar los fondos a una wallet nueva."
    );
  }

  const privateKey = decryptV3(keystore, passphrase);
  const wallet = privateKeyToWallet(privateKey);

  console.log("");
  console.log(`Archivo   : ${file}`);
  console.log(`Dirección : ${wallet.address}`);
  console.log(`Clave priv: ${wallet.privateKey}`);
  console.log("");

  if (showKeyQR) {
    qrcode.generate(wallet.privateKey, { small: true }, (qr) => {
      console.log("\tClave privada (no fotografiar ni compartir)");
      console.log(qr);
    });
  }
} catch (error) {
  console.error(`\nError: ${error.message}`);
  process.exitCode = 1;
} finally {
  closePrompt();
}
