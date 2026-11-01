import { secp256k1 } from "@noble/curves/secp256k1.js";

/**
 * Fuente de aleatoriedad: `crypto.getRandomValues` del runtime.
 *
 * Es el único generador aceptado. En Node (>= 19) y en los navegadores es la
 * misma función, respaldada por el CSPRNG del sistema operativo
 * (getrandom(2) / BCryptGenRandom / SecRandomCopyBytes).
 *
 * NUNCA usar `Math.random()`: no es criptográfico, es predecible a partir de
 * unas pocas salidas y no tiene cabida en la generación de claves.
 */
export function randomBytes(length) {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== "function") {
    throw new Error(
      "El runtime no expone crypto.getRandomValues: no se puede generar aleatoriedad segura."
    );
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Clave privada válida para secp256k1: 32 bytes uniformes en el rango [1, n-1],
 * donde n es el orden del grupo.
 *
 * Se usa rechazo en lugar de reducir módulo n: reducir introduce un sesgo de
 * ~2^-128 por muestra, pero el rechazo es más simple de auditar y el coste es
 * despreciable (la probabilidad de descartar una muestra es ~2^-128).
 */
export function randomPrivateKey() {
  for (;;) {
    const candidate = randomBytes(32);
    if (secp256k1.utils.isValidSecretKey(candidate)) {
      return candidate;
    }
  }
}

/** Orden del grupo secp256k1 (n), en hex. Útil para tests. */
export function curveOrder() {
  return secp256k1.Point.CURVE().n;
}
