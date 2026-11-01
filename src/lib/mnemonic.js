import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { bytesToHex } from "@noble/hashes/utils.js";
import { randomBytes } from "./random.js";
import { privateKeyToAddress } from "./wallet.js";

/** Ruta estándar de Ethereum para la primera cuenta externa (BIP-44). */
export const ETHEREUM_PATH = "m/44'/60'/0'/0/0";

/**
 * Genera un mnemonic BIP-39. 256 bits de entropía => 24 palabras.
 *
 * La semilla se obtiene del mnemonic, no al revés: el mnemonic ES el respaldo.
 * Si se pierde, la wallet se pierde; si se filtra, los fondos también.
 */
export function generateMnemonic(strength = 256) {
  const entropy = randomBytes(strength / 8);
  const mnemonic = entropyToMnemonic(entropy, wordlist);
  entropy.fill(0);
  return { mnemonic, words: mnemonic.split(" ").length };
}

/**
 * Deriva la clave privada desde un mnemonic:
 *   seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 iteraciones)
 *   clave = BIP-32(seed) en la ruta m/44'/60'/0'/0/0
 *
 * `passphrase` es la palabra de paso BIP-39 opcional (distinta de la frase de
 * cifrado del keystore). Si se usa al crear, hay que usarla también al restaurar.
 */
export function mnemonicToWallet(mnemonic, passphrase = "") {
  if (typeof passphrase !== "string") {
    throw new Error("La palabra de paso BIP-39 debe ser texto.");
  }
  // BIP-39 exige normalización NFKD antes de derivar la semilla.
  const phrase = String(mnemonic)
    .normalize("NFKD")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
  if (!validateMnemonic(phrase, wordlist)) {
    throw new Error("Mnemonic BIP-39 inválido: palabra desconocida o checksum incorrecto.");
  }

  const seed = mnemonicToSeedSync(phrase, passphrase.normalize("NFKD"));
  const root = HDKey.fromMasterSeed(seed);
  const node = root.derive(ETHEREUM_PATH);
  const privateKey = node.privateKey;
  seed.fill(0);
  node.wipePrivateData();
  root.wipePrivateData();

  if (!privateKey) {
    throw new Error("No se pudo derivar la clave privada de la ruta BIP-44.");
  }

  return {
    mnemonic: phrase,
    path: ETHEREUM_PATH,
    privateKey: "0x" + bytesToHex(privateKey),
    address: privateKeyToAddress(privateKey),
  };
}

/** Wallet completa: mnemonic, ruta BIP-44, clave privada y dirección. */
export function generateMnemonicWallet(passphrase = "") {
  const { mnemonic, words } = generateMnemonic(256);
  return { ...mnemonicToWallet(mnemonic, passphrase), words };
}
