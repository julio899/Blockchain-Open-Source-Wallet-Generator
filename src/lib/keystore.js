import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
  pbkdf2Sync,
} from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { normalizePrivateKey, privateKeyToAddress } from "./wallet.js";

/**
 * Web3 Secret Storage V3 (el keystore de geth/MetaMask), con parámetros
 * endurecidos:
 *
 *   kdf:    scrypt  N=2^17, r=8, p=1, dklen=32   (antes N=8192: 16x más débil)
 *   cipher: aes-128-ctr
 *   mac:    keccak256(dk[16..32] || ciphertext)
 *
 * Se mantiene el formato estándar a propósito: el archivo se puede importar en
 * MetaMask, geth, ethers, etc. El MAC sí detecta manipulación del ciphertext,
 * aunque no es AEAD como AES-GCM.
 */

export const SCRYPT_PARAMS = Object.freeze({ n: 2 ** 17, r: 8, p: 1, dklen: 32 });
const CIPHER = "aes-128-ctr";
const MIN_PASSWORD_LENGTH = 12;
const MAX_MEMORY = 1024 * 1024 * 1024; // 1 GiB: techo duro contra keystores maliciosos

export class KeystoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "KeystoreError";
  }
}

function scrypt(password, salt, { n, r, p, dklen }) {
  const required = 128 * n * r * 2; // el doble del mínimo exigido por OpenSSL
  return scryptSync(password, salt, dklen, {
    N: n,
    r,
    p,
    maxmem: Math.max(required, 32 * 1024 * 1024),
  });
}

/**
 * Convierte un campo hexadecimal del keystore a Buffer, aceptando el prefijo
 * "0x" y mayúsculas (hay exportadores que los usan) y validando el tamaño.
 */
function hexBuffer(value, field, minBytes, maxBytes) {
  if (typeof value !== "string") {
    throw new KeystoreError(`Campo '${field}' ausente en el keystore.`);
  }
  const hex = value.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new KeystoreError(`Campo '${field}' no es hexadecimal válido.`);
  }
  const bytes = hex.length / 2;
  if (bytes < minBytes || bytes > maxBytes) {
    throw new KeystoreError(`Campo '${field}' con tamaño inesperado.`);
  }
  return Buffer.from(hex, "hex");
}

/**
 * Informa de los parámetros KDF de un keystore sin descifrarlo, para avisar de
 * los archivos viejos con scrypt N=8192.
 */
export function inspectKeystore(keystore) {
  const section = keystore?.crypto ?? keystore?.Crypto ?? {};
  const params = section.kdfparams ?? {};
  const n = params.n ?? params.N;

  return {
    kdf: section.kdf,
    n: Number.isInteger(n) ? n : null,
    r: params.r ?? null,
    p: params.p ?? null,
    c: params.c ?? null,
    weak:
      section.kdf === "scrypt"
        ? !Number.isInteger(n) || n < SCRYPT_PARAMS.n
        : !Number.isInteger(params.c) || params.c < 600_000,
  };
}

function validateKdfParams(kdfparams) {
  const { dklen = 32, n, r, p } = kdfparams ?? {};

  if (!Number.isInteger(n) || n < 2 || n > 2 ** 20 || (n & (n - 1)) !== 0) {
    throw new KeystoreError("Parámetro 'n' del KDF inválido o fuera de rango.");
  }
  if (!Number.isInteger(r) || r < 1 || r > 32) {
    throw new KeystoreError("Parámetro 'r' del KDF inválido o fuera de rango.");
  }
  if (!Number.isInteger(p) || p < 1 || p > 8) {
    throw new KeystoreError("Parámetro 'p' del KDF inválido o fuera de rango.");
  }
  if (!Number.isInteger(dklen) || dklen < 32 || dklen > 64) {
    throw new KeystoreError("Parámetro 'dklen' del KDF inválido o fuera de rango.");
  }
  if (128 * n * r > MAX_MEMORY) {
    throw new KeystoreError("El keystore pide más memoria de la permitida para derivar la clave.");
  }
}

function deriveKey(password, salt, kdfparams) {
  return scrypt(Buffer.from(password, "utf8"), salt, kdfparams);
}

function computeMac(derivedKey, ciphertext) {
  return Buffer.from(keccak_256(concatBytes(derivedKey.subarray(16, 32), ciphertext)));
}

/** Cifra una clave privada en el formato V3 con scrypt N=2^17. */
export function encryptV3(privateKeyInput, password) {
  const privateKey = normalizePrivateKey(privateKeyInput);

  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    throw new KeystoreError(
      `La frase de cifrado debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres.`
    );
  }

  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const kdfparams = { ...SCRYPT_PARAMS, salt: salt.toString("hex") };
  const derivedKey = scrypt(Buffer.from(password, "utf8"), salt, SCRYPT_PARAMS);

  const cipher = createCipheriv(CIPHER, derivedKey.subarray(0, 16), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(privateKey)), cipher.final()]);
  const mac = computeMac(derivedKey, ciphertext);
  derivedKey.fill(0);

  return {
    version: 3,
    id: randomUUID(),
    address: privateKeyToAddress(privateKey).slice(2).toLowerCase(),
    crypto: {
      cipher: CIPHER,
      cipherparams: { iv: iv.toString("hex") },
      ciphertext: ciphertext.toString("hex"),
      kdf: "scrypt",
      kdfparams,
      mac: mac.toString("hex"),
    },
  };
}

/**
 * Descifra un keystore V3. Acepta los parámetros que traiga el archivo (por eso
 * lee los keystores antiguos con N=8192), pero los valida antes de derivar para
 * que un archivo malicioso no agote la memoria del equipo.
 */
export function decryptV3(keystore, password) {
  if (!keystore || typeof keystore !== "object") {
    throw new KeystoreError("Keystore vacío o ilegible.");
  }
  if (typeof password !== "string") {
    throw new KeystoreError("Falta la frase de cifrado.");
  }
  if (Number(keystore.version) !== 3) {
    throw new KeystoreError(`Versión de keystore no soportada: ${keystore.version}.`);
  }

  const cryptoSection = keystore.crypto ?? keystore.Crypto;
  if (!cryptoSection || typeof cryptoSection !== "object") {
    throw new KeystoreError("El keystore no contiene la sección 'crypto'.");
  }
  if (cryptoSection.kdf !== "scrypt" && cryptoSection.kdf !== "pbkdf2") {
    throw new KeystoreError(`KDF no soportado: ${cryptoSection.kdf}.`);
  }
  if (cryptoSection.cipher !== CIPHER) {
    throw new KeystoreError(`Cifrado no soportado: ${cryptoSection.cipher}.`);
  }

  const rawParams = cryptoSection.kdfparams ?? {};
  // Algunos exportadores escriben "N" en mayúscula y/o prefijos 0x: se aceptan.
  const kdfparams = { ...rawParams, n: rawParams.n ?? rawParams.N };
  let derivedKey;

  if (cryptoSection.kdf === "scrypt") {
    validateKdfParams(kdfparams);
    const salt = hexBuffer(kdfparams.salt, "salt", 16, 64);
    derivedKey = deriveKey(password, salt, kdfparams);
  } else {
    // Compatibilidad: algunos keystores usan PBKDF2-HMAC-SHA256.
    const c = kdfparams.c;
    const dklen = kdfparams.dklen ?? 32;
    if (!Number.isInteger(c) || c < 1000 || c > 5_000_000) {
      throw new KeystoreError("Parámetro 'c' del KDF PBKDF2 inválido.");
    }
    if (kdfparams.prf !== "hmac-sha256") {
      throw new KeystoreError(`PRF no soportado: ${kdfparams.prf}.`);
    }
    derivedKey = pbkdf2Sync(
      Buffer.from(password, "utf8"),
      hexBuffer(kdfparams.salt, "salt", 16, 64),
      c,
      dklen,
      "sha256"
    );
  }

  const ciphertext = hexBuffer(cryptoSection.ciphertext, "ciphertext", 32, 32);
  const expectedMac = computeMac(derivedKey, ciphertext);
  const storedMac = hexBuffer(cryptoSection.mac, "mac", 32, 32);

  const macMatches =
    storedMac.length === expectedMac.length && timingSafeEqual(storedMac, expectedMac);

  if (!macMatches) {
    derivedKey.fill(0);
    throw new KeystoreError("Frase incorrecta o archivo dañado (el MAC no coincide).");
  }

  const decipher = createDecipheriv(
    CIPHER,
    derivedKey.subarray(0, 16),
    hexBuffer(cryptoSection.cipherparams?.iv, "iv", 16, 16)
  );
  const privateKey = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  derivedKey.fill(0);

  const normalized = normalizePrivateKey(new Uint8Array(privateKey));

  // El keystore declara la dirección: si no coincide con la clave descifrada,
  // el archivo fue manipulado o no corresponde.
  if (typeof keystore.address === "string") {
    const declared = "0x" + keystore.address.replace(/^0x/i, "").toLowerCase();
    if (declared !== privateKeyToAddress(normalized).toLowerCase()) {
      privateKey.fill(0);
      throw new KeystoreError("La dirección del keystore no coincide con la clave descifrada.");
    }
  }

  privateKey.fill(0);
  return normalized;
}
