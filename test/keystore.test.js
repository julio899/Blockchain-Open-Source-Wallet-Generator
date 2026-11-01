import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, randomBytes, scryptSync } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { encryptV3, decryptV3, inspectKeystore, KeystoreError, SCRYPT_PARAMS } from "../src/lib/keystore.js";
import { privateKeyToAddress } from "../src/lib/wallet.js";

const PASSWORD = "frase-de-prueba-larga";
const PRIVATE_KEY = "0x" + "11".repeat(32);

/** Keystore como lo generaba web3 1.8.1: scrypt N=8192, r=8, p=1. */
function legacyKeystore(privateKeyHex, password, n = 8192) {
  const privateKey = Buffer.from(privateKeyHex.replace(/^0x/, ""), "hex");
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derivedKey = scryptSync(Buffer.from(password, "utf8"), salt, 32, {
    N: n,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });

  const cipher = createCipheriv("aes-128-ctr", derivedKey.subarray(0, 16), iv);
  const ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  const mac = Buffer.from(keccak_256(concatBytes(derivedKey.subarray(16, 32), ciphertext)));

  return {
    version: 3,
    id: "00000000-0000-4000-8000-000000000000",
    address: privateKeyToAddress(new Uint8Array(privateKey)).slice(2).toLowerCase(),
    crypto: {
      cipher: "aes-128-ctr",
      cipherparams: { iv: iv.toString("hex") },
      ciphertext: ciphertext.toString("hex"),
      kdf: "scrypt",
      kdfparams: { dklen: 32, salt: salt.toString("hex"), n, r: 8, p: 1 },
      mac: mac.toString("hex"),
    },
  };
}

test("cifra y descifra con scrypt N=2^17", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);

  assert.equal(keystore.version, 3);
  assert.equal(keystore.crypto.kdfparams.n, SCRYPT_PARAMS.n);
  assert.equal(keystore.crypto.kdfparams.n, 131072);
  assert.equal(keystore.crypto.cipher, "aes-128-ctr");

  const privateKey = decryptV3(keystore, PASSWORD);
  assert.equal("0x" + bytesToHex(privateKey), PRIVATE_KEY);
});

test("el archivo cifrado no contiene la clave privada en claro", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  assert.equal(JSON.stringify(keystore).includes(PRIVATE_KEY.slice(2)), false);
});

test("una frase incorrecta no descifra", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  assert.throws(() => decryptV3(keystore, "frase-incorrecta-x"), KeystoreError);
});

test("un keystore manipulado no descifra", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  const tampered = structuredClone(keystore);
  tampered.crypto.ciphertext =
    (tampered.crypto.ciphertext[0] === "0" ? "1" : "0") + tampered.crypto.ciphertext.slice(1);
  assert.throws(() => decryptV3(tampered, PASSWORD), /MAC no coincide/);
});

test("una frase corta se rechaza al cifrar", () => {
  assert.throws(() => encryptV3(PRIVATE_KEY, "corta"), /al menos 12/);
});

test("compatibilidad: descifra un keystore antiguo con scrypt N=8192", () => {
  const legacy = legacyKeystore(PRIVATE_KEY, PASSWORD, 8192);
  const privateKey = decryptV3(legacy, PASSWORD);
  assert.equal("0x" + bytesToHex(privateKey), PRIVATE_KEY);
});

test("un keystore con parámetros KDF abusivos se rechaza sin reservar memoria", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  const hostile = structuredClone(keystore);
  hostile.crypto.kdfparams.n = 2 ** 30;

  const started = Date.now();
  assert.throws(() => decryptV3(hostile, PASSWORD), KeystoreError);
  assert.ok(Date.now() - started < 1000, "debe rechazar antes de derivar la clave");
});

test("una dirección declarada distinta a la clave descifrada se rechaza", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  const other = encryptV3("0x" + "22".repeat(32), PASSWORD);
  const swapped = { ...keystore, address: other.address };
  assert.throws(() => decryptV3(swapped, PASSWORD), /no coincide/);
});

test("acepta keystores con la sección 'Crypto' en mayúscula (formato geth)", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  const { crypto, ...rest } = keystore;
  const reordered = { ...rest, Crypto: crypto };
  assert.equal("0x" + bytesToHex(decryptV3(reordered, PASSWORD)), PRIVATE_KEY);
});

test("rechaza una versión de keystore no soportada", () => {
  assert.throws(() => decryptV3({ version: 4 }, PASSWORD), /no soportada/);
});

test("acepta hex con prefijo 0x y mayúsculas (exportadores heterogéneos)", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  const variant = structuredClone(keystore);
  variant.version = "3";
  variant.crypto.ciphertext = "0x" + variant.crypto.ciphertext.toUpperCase();
  variant.crypto.mac = "0x" + variant.crypto.mac.toUpperCase();
  variant.crypto.kdfparams.salt = "0x" + variant.crypto.kdfparams.salt.toUpperCase();
  variant.crypto.cipherparams.iv = "0x" + variant.crypto.cipherparams.iv.toUpperCase();
  variant.crypto.kdfparams.N = variant.crypto.kdfparams.n;
  delete variant.crypto.kdfparams.n;

  assert.equal("0x" + bytesToHex(decryptV3(variant, PASSWORD)), PRIVATE_KEY);
});

test("inspectKeystore marca como débil el scrypt N=8192 y como fuerte el N=2^17", () => {
  const debil = legacyKeystore(PRIVATE_KEY, PASSWORD, 8192);
  const fuerte = encryptV3(PRIVATE_KEY, PASSWORD);

  assert.equal(inspectKeystore(debil).weak, true);
  assert.equal(inspectKeystore(debil).n, 8192);
  assert.equal(inspectKeystore(fuerte).weak, false);
  assert.equal(inspectKeystore(fuerte).n, 131072);
});
