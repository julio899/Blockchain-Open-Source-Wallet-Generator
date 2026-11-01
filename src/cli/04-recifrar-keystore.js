#!/usr/bin/env node
import { normalizeAddress, privateKeyToWallet } from "../lib/wallet.js";
import { ask, askSecret, askPassphrase, closePrompt } from "../lib/prompt.js";
import { decryptV3, encryptV3, inspectKeystore } from "../lib/keystore.js";
import { readKeystore, writeKeystore } from "../lib/storage.js";

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(`Uso: node src/cli/04-recifrar-keystore.js

Vuelve a cifrar un keystore con los parámetros actuales (scrypt N=2^17) sin
borrar el archivo original. Útil para keystores creados por la versión 1, que
usaba N=8192.

El archivo nuevo se escribe junto al anterior: wallets/<dirección>-encrypt.json
solo si ese nombre está libre; si no, se indica al usuario que mueva el viejo
a mano.

Opciones:
  -h, --help   Esta ayuda`);
  process.exit(0);
}

process.umask(0o077);

try {
  const addressInput = await ask("Dirección del keystore a recifrar (0x…): ");
  const address = normalizeAddress(addressInput);

  const { file, keystore } = readKeystore(address);
  const info = inspectKeystore(keystore);

  console.log("");
  console.log(`Archivo   : ${file}`);
  console.log(`KDF actual: ${info.kdf} n=${info.n ?? "-"} r=${info.r ?? "-"} p=${info.p ?? "-"}`);

  if (!info.weak) {
    console.log("\nEste keystore ya usa parámetros fuertes. No hace falta recifrarlo.");
    process.exitCode = 0;
  } else {
    const oldPassphrase = await askSecret("Frase actual: ");
    const privateKey = decryptV3(keystore, oldPassphrase);

    const newPassphrase = await askPassphrase("Nueva frase de cifrado: ");
    const recifrado = encryptV3(privateKey, newPassphrase);
    const wallet = privateKeyToWallet(privateKey);
    privateKey.fill(0);

    // Se escribe con un nombre distinto para no destruir el original.
    const destino = writeKeystore(wallet.address, recifrado, undefined, "-recifrado");

    console.log("");
    console.log(`Nuevo archivo: ${destino}`);
    console.log("El archivo original NO se ha borrado. Cuando compruebe que el nuevo");
    console.log("abre bien, sustituya el viejo con:");
    console.log("");
    console.log(`  mv ${file} ${file}.v1.bak`);
    console.log(`  mv ${destino} ${file}`);
    console.log("");
    console.log("Aviso: si la clave o la frase antigua aparecieron en logs, QR o capturas,");
    console.log("recifrar no deshace esa exposición. Considere pasar los fondos a una");
    console.log("wallet generada de nuevo.");
  }
} catch (error) {
  console.error(`\nError: ${error.message}`);
  process.exitCode = 1;
} finally {
  closePrompt();
}
