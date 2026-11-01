import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  keystorePath,
  findKeystoreFile,
  writeKeystore,
  readKeystore,
  StorageError,
} from "../src/lib/storage.js";
import { encryptV3 } from "../src/lib/keystore.js";

const ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
const PASSWORD = "frase-de-prueba-larga";
const PRIVATE_KEY = "0x" + "00".repeat(31) + "01";

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "wallet-storage-"));
}

test("escribe el keystore con permisos 0600 y el directorio con 0700", () => {
  const dir = tempDir();
  const file = writeKeystore(ADDRESS, encryptV3(PRIVATE_KEY, PASSWORD), dir);

  const fileMode = fs.statSync(file).mode & 0o777;
  const dirMode = fs.statSync(dir).mode & 0o777;

  assert.equal(fileMode, 0o600, "el keystore debe ser solo del usuario");
  assert.equal(dirMode, 0o700, "el directorio debe ser solo del usuario");
});

test("no sobrescribe un keystore existente", () => {
  const dir = tempDir();
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  writeKeystore(ADDRESS, keystore, dir);

  assert.throws(() => writeKeystore(ADDRESS, keystore, dir), /Ya existe/);
  assert.equal(fs.readdirSync(dir).length, 1);
});

test("la ruta solo se construye con direcciones válidas", () => {
  for (const bad of ["../../etc/passwd", "/etc/passwd", "0x1234", "../wallets"]) {
    assert.throws(() => keystorePath(bad), /Dirección inválida/);
  }
});

test("encuentra keystores antiguos con el nombre en mayúsculas", () => {
  const dir = tempDir();
  // La versión 1 usaba la dirección con checksum en el nombre del archivo.
  const legado = path.join(dir, `${ADDRESS}-encrypt.json`);
  fs.writeFileSync(legado, JSON.stringify(encryptV3(PRIVATE_KEY, PASSWORD)));

  const found = findKeystoreFile(ADDRESS.toLowerCase(), dir);
  assert.equal(fs.realpathSync(found), fs.realpathSync(legado));

  const { keystore } = readKeystore(ADDRESS, dir);
  assert.equal(keystore.version, 3);
});

test("rechaza un symlink que apunte fuera del directorio", () => {
  const dir = tempDir();
  const outside = path.join(tempDir(), "afuera.json");
  fs.writeFileSync(outside, JSON.stringify(encryptV3(PRIVATE_KEY, PASSWORD)));

  fs.symlinkSync(outside, path.join(dir, `${ADDRESS.toLowerCase()}-encrypt.json`));

  assert.throws(() => findKeystoreFile(ADDRESS, dir), StorageError);
});

test("rechaza un archivo demasiado grande", () => {
  const dir = tempDir();
  const big = path.join(dir, `${ADDRESS.toLowerCase()}-encrypt.json`);
  fs.writeFileSync(big, "{" + " ".repeat(70 * 1024) + "}");

  assert.throws(() => readKeystore(ADDRESS, dir), /demasiado grande/);
});

test("avisa cuando falta el directorio de wallets", () => {
  const dir = path.join(tempDir(), "no-existe");
  assert.throws(() => findKeystoreFile(ADDRESS, dir), /No existe el directorio/);
});

test("rechaza un JSON inválido con un error claro", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, `${ADDRESS.toLowerCase()}-encrypt.json`), "{ no es json");

  assert.throws(() => readKeystore(ADDRESS, dir), /no es un JSON válido/);
});

test("crea directorios anidados con permisos 0700", () => {
  const base = path.join(tempDir(), "a", "b");
  const file = writeKeystore(ADDRESS, encryptV3(PRIVATE_KEY, PASSWORD), base);

  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(base).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.dirname(base)).mode & 0o777, 0o700);
});

test("no sigue un symlink colocado en la ruta de destino", () => {
  const dir = tempDir();
  const objetivo = path.join(tempDir(), "objetivo.json");
  fs.writeFileSync(objetivo, "original");
  fs.symlinkSync(objetivo, path.join(dir, `${ADDRESS.toLowerCase()}-encrypt.json`));

  assert.throws(() => writeKeystore(ADDRESS, encryptV3(PRIVATE_KEY, PASSWORD), dir), /Ya existe/);
  assert.equal(fs.readFileSync(objetivo, "utf8"), "original");
});

test("readKeystore acepta la dirección con checksum en el nombre del archivo", () => {
  const dir = tempDir();
  // Nombre con la dirección en mayúsculas y minúsculas, como generaba la v1.
  fs.writeFileSync(
    path.join(dir, `${ADDRESS}-encrypt.json`),
    JSON.stringify(encryptV3(PRIVATE_KEY, PASSWORD))
  );

  const { file } = readKeystore(ADDRESS.toLowerCase(), dir);
  assert.match(file, /0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf-encrypt\.json$/);
});
