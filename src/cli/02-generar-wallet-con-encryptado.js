#!/usr/bin/env node
import { randomPrivateKey } from "../lib/random.js";
import { privateKeyToWallet } from "../lib/wallet.js";
import { generateMnemonicWallet } from "../lib/mnemonic.js";
import { askPassphrase, closePrompt } from "../lib/prompt.js";
import { encryptV3 } from "../lib/keystore.js";
import { writeKeystore } from "../lib/storage.js";

const args = new Set(process.argv.slice(2));

if (args.has("--help") || args.has("-h")) {
  console.log(`Uso: node src/cli/02-generar-wallet-con-encryptado.js [--mnemonic]

Genera una wallet, la cifra con una frase que se pide por terminal (sin echo) y
la guarda en wallets/<dirección>-encrypt.json con permisos 0600.

El archivo resultante es un keystore Web3 Secret Storage V3 (importable en
MetaMask o geth) con scrypt N=2^17.

Opciones:
  --mnemonic   Genera la wallet desde un mnemonic BIP-39 de 24 palabras
  -h, --help   Esta ayuda`);
  process.exit(0);
}

// Los archivos que se creen a partir de aquí solo los puede leer el usuario.
process.umask(0o077);

const useMnemonic = args.has("--mnemonic");

try {
  const wallet = useMnemonic
    ? generateMnemonicWallet()
    : privateKeyToWallet(randomPrivateKey());

  const passphrase = await askPassphrase();
  const keystore = encryptV3(wallet.privateKey, passphrase);
  const file = writeKeystore(wallet.address, keystore);

  console.log("");
  console.log(`Dirección : ${wallet.address}`);
  console.log(`Archivo   : ${file}`);
  console.log("");
  console.log("La frase de cifrado no se ha guardado en ningún sitio.");
  console.log("Sin esa frase el archivo no se puede abrir: guárdela por separado.");
  console.log("No se muestra la clave privada: el keystore cifrado es el respaldo.");
} catch (error) {
  console.error(`\nError: ${error.message}`);
  process.exitCode = 1;
} finally {
  closePrompt();
}
