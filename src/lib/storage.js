import fs from "node:fs";
import path from "node:path";
import { normalizeAddress } from "./wallet.js";

export const WALLETS_DIR = "wallets";
const SUFFIX = "-encrypt.json";
// Un keystore V3 real ocupa ~1 KiB; el límite evita leer un archivo enorme
// puesto ahí como ataque de agotamiento de memoria.
const MAX_KEYSTORE_BYTES = 64 * 1024;

export class StorageError extends Error {
  constructor(message) {
    super(message);
    this.name = "StorageError";
  }
}

/**
 * La ruta se construye SIEMPRE desde una dirección ya validada (0x + 40 hex),
 * nunca desde la entrada cruda del usuario: así no hay "..%2f" ni rutas
 * absolutas que escapen de wallets/.
 */
export function keystorePath(address, baseDir = WALLETS_DIR, suffix = "") {
  return path.join(baseDir, `${normalizeAddress(address)}${suffix}${SUFFIX}`);
}

/** Busca el archivo aceptando mayúsculas/minúsculas (keystores antiguos). */
export function findKeystoreFile(address, baseDir = WALLETS_DIR) {
  const expected = path.basename(keystorePath(address, baseDir)).toLowerCase();

  if (!fs.existsSync(baseDir)) {
    throw new StorageError(`No existe el directorio ${baseDir}/.`);
  }

  const found = fs.readdirSync(baseDir).find((name) => name.toLowerCase() === expected);
  if (!found) {
    throw new StorageError(`No se encontró ${expected} en ${baseDir}/.`);
  }

  const file = path.join(baseDir, found);

  // Un symlink permitiría apuntar fuera de wallets/ y leer otro archivo.
  const stat = fs.lstatSync(file);
  if (!stat.isFile()) {
    throw new StorageError(`${file} no es un archivo regular.`);
  }

  // Comprobación final: la ruta real debe seguir dentro de wallets/.
  const realDir = fs.realpathSync(path.dirname(file));
  if (realDir !== fs.realpathSync(baseDir)) {
    throw new StorageError(`La ruta de ${file} queda fuera de ${baseDir}/.`);
  }

  return file;
}

/**
 * Escribe el keystore con permisos 0600 (solo el usuario) y sin sobrescribir:
 * `wx` falla si el archivo ya existe, para no destruir una copia válida.
 */
export function writeKeystore(address, keystore, baseDir = WALLETS_DIR, suffix = "") {
  fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(baseDir, 0o700);

  const file = keystorePath(address, baseDir, suffix);
  const payload = JSON.stringify(keystore, null, 2) + "\n";

  try {
    fs.writeFileSync(file, payload, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error.code === "EEXIST") {
      throw new StorageError(`Ya existe ${file}. No se sobrescribe.`);
    }
    throw error;
  }

  // El modo pasado a writeFileSync se recorta con el umask; se reafirma.
  fs.chmodSync(file, 0o600);
  return file;
}

export function readKeystore(address, baseDir = WALLETS_DIR) {
  const file = findKeystoreFile(address, baseDir);

  if (fs.statSync(file).size > MAX_KEYSTORE_BYTES) {
    throw new StorageError(`${file} es demasiado grande para ser un keystore.`);
  }

  try {
    return { file, keystore: JSON.parse(fs.readFileSync(file, "utf8")) };
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new StorageError(`El archivo ${file} no es un JSON válido.`);
    }
    throw error;
  }
}
