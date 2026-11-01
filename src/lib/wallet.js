import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const HEX_40 = /^[0-9a-f]{40}$/;
const WITH_PREFIX = /^0x[0-9a-fA-F]{40}$/;

/**
 * EIP-55: la dirección en minúsculas se hashea con keccak256 y cada nibble del
 * hash decide si el carácter correspondiente de la dirección va en mayúscula
 * (dígito del hash >= 8). Así un error de tipeo en la dirección se detecta.
 *
 * Ojo: keccak256 != SHA3-256. OpenSSL/Node solo exponen SHA3-256 (NIST), que
 * produce direcciones distintas. Por eso se usa @noble/hashes.
 */
export function toChecksumAddress(address) {
  const lower = String(address).replace(/^0x/i, "").toLowerCase();
  if (!HEX_40.test(lower)) {
    throw new Error(`Dirección inválida: se esperaban 40 caracteres hexadecimales.`);
  }

  const hash = bytesToHex(keccak_256(utf8ToBytes(lower)));
  let checksummed = "0x";
  for (let i = 0; i < 40; i++) {
    checksummed += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return checksummed;
}

/**
 * Deriva la dirección desde la clave privada:
 *   pubkey = secp256k1(priv)            -> 65 bytes 0x04 || X || Y
 *   address = keccak256(X || Y)[12..32] -> últimos 20 bytes, en formato EIP-55
 */
export function privateKeyToAddress(privateKey) {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  const hash = keccak_256(publicKey.slice(1));
  return toChecksumAddress(bytesToHex(hash.slice(-20)));
}

/** Devuelve un objeto con la clave privada serializada (0x + 64 hex) y la dirección. */
export function privateKeyToWallet(privateKey) {
  return {
    address: privateKeyToAddress(privateKey),
    privateKey: "0x" + bytesToHex(privateKey),
  };
}

/**
 * Acepta una clave privada como Uint8Array o como cadena "0x…"/64 hex.
 * Valida longitud y rango [1, n-1].
 */
export function normalizePrivateKey(input) {
  if (input instanceof Uint8Array) {
    if (input.length !== 32 || !secp256k1.utils.isValidSecretKey(input)) {
      throw new Error("Clave privada fuera del rango válido de secp256k1.");
    }
    return input;
  }

  if (typeof input === "string") {
    const hex = input.trim().replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error("La clave privada debe tener 64 caracteres hexadecimales.");
    }
    return normalizePrivateKey(hexToBytes(hex));
  }

  throw new Error("Formato de clave privada no soportado.");
}

/** Comprueba forma y checksum EIP-55 (si la cadena viene en minúsculas se acepta). */
export function isValidAddress(input) {
  if (typeof input !== "string" || !WITH_PREFIX.test(input)) return false;
  const body = input.slice(2);
  // Una dirección toda en minúsculas o toda en mayúsculas es válida sin checksum.
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  return toChecksumAddress(body) === input;
}

/**
 * Normaliza a la forma "0x" + minúsculas, validando el checksum cuando la
 * entrada viene en mixta. Devuelve solo esta forma: nunca se construye una ruta
 * de archivo con la entrada cruda del usuario.
 */
export function normalizeAddress(input) {
  const value = String(input ?? "").trim();
  if (!WITH_PREFIX.test(value)) {
    throw new Error("Dirección inválida: se esperaba el formato 0x + 40 caracteres hexadecimales.");
  }
  if (!isValidAddress(value)) {
    throw new Error("El checksum EIP-55 de la dirección no es válido (posible error de tipeo).");
  }
  return value.toLowerCase();
}
