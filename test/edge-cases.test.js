import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { concatBytes } from "@noble/hashes/utils.js";
import {
  normalizePrivateKey,
  normalizeAddress,
  toChecksumAddress,
  isValidAddress,
  privateKeyToAddress,
} from "../src/lib/wallet.js";
import {
  encryptV3,
  decryptV3,
  inspectKeystore,
  KeystoreError,
} from "../src/lib/keystore.js";
import {
  generateMnemonic,
  mnemonicToWallet,
  ETHEREUM_PATH,
} from "../src/lib/mnemonic.js";
import { randomPrivateKey, randomBytes as csprng } from "../src/lib/random.js";
import { ask, askSecret, askPassphrase } from "../src/lib/prompt.js";

const PASSWORD = "frase-de-prueba-larga";
const PRIVATE_KEY = "0x" + "11".repeat(32);
const ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// ---------------------------------------------------------------- claves

test("normalizePrivateKey rechaza longitudes y valores fuera de rango", () => {
  const casos = [
    "0x" + "11".repeat(31), // 31 bytes
    "0x" + "11".repeat(33), // 33 bytes
    "0x" + "00".repeat(32), // cero
    "0x" + ORDER.toString(16).padStart(64, "0"), // exactamente n
    "0x" + "ff".repeat(32), // > n
    "0xzz", // no hexadecimal
    "",
    null,
    123,
    {},
  ];

  for (const caso of casos) {
    assert.throws(() => normalizePrivateKey(caso), `debe rechazar ${String(caso)}`);
  }
});

test("normalizePrivateKey acepta Uint8Array y cadena con o sin 0x", () => {
  const bytes = new Uint8Array(32).fill(0x11);
  assert.deepEqual(normalizePrivateKey(bytes), bytes);
  assert.deepEqual(normalizePrivateKey("11".repeat(32)), bytes);
  assert.deepEqual(normalizePrivateKey("0x" + "11".repeat(32)), bytes);
  assert.deepEqual(normalizePrivateKey("  0X" + "11".repeat(32) + "  "), bytes);
});

test("normalizePrivateKey rechaza el límite superior exacto del grupo", () => {
  const nMenosUno = (ORDER - 1n).toString(16).padStart(64, "0");
  assert.equal(normalizePrivateKey("0x" + nMenosUno).length, 32);
});

// ------------------------------------------------------------ direcciones

test("normalizeAddress exige el prefijo 0x y el checksum cuando es mixta", () => {
  assert.throws(() => normalizeAddress("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), /0x/);
  assert.throws(
    () => normalizeAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"),
    /checksum/
  );
  assert.throws(() => normalizeAddress(undefined), /Dirección inválida/);
  assert.throws(() => normalizeAddress(42), /Dirección inválida/);
});

test("normalizeAddress acepta formas todo-minúsculas y todo-mayúsculas", () => {
  const lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
  const upper = "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED";
  assert.equal(normalizeAddress(lower), lower);
  assert.equal(normalizeAddress(upper), lower);
  assert.equal(normalizeAddress("  " + lower + "\n"), lower);
});

test("toChecksumAddress rechaza cuerpos de longitud incorrecta", () => {
  for (const bad of ["0x", "1234", "0x" + "a".repeat(39), "0x" + "a".repeat(41)]) {
    assert.throws(() => toChecksumAddress(bad), /Dirección inválida/);
  }
});

test("isValidAddress no lanza con entradas raras", () => {
  for (const bad of [null, undefined, 0, [], {}, "0xzz"]) {
    assert.doesNotThrow(() => isValidAddress(bad));
    assert.equal(isValidAddress(bad), false);
  }
});

test("la dirección derivada es determinista para la misma clave", () => {
  for (let i = 0; i < 50; i++) {
    const key = randomPrivateKey();
    assert.equal(privateKeyToAddress(key), privateKeyToAddress(Uint8Array.from(key)));
  }
});

// -------------------------------------------------------------- mnemonic

test("generateMnemonic soporta 12 y 24 palabras", () => {
  const doce = generateMnemonic(128);
  const veinticuatro = generateMnemonic(256);

  assert.equal(doce.words, 12);
  assert.equal(veinticuatro.words, 24);
  assert.equal(mnemonicToWallet(doce.mnemonic).address.startsWith("0x"), true);
  assert.equal(mnemonicToWallet(veinticuatro.mnemonic).address.startsWith("0x"), true);
});

test("mnemonicToWallet rechaza longitud, palabras y checksum inválidos", () => {
  const casos = [
    "",
    "abandon abandon",
    "noexiste noexiste noexiste noexiste noexiste noexiste noexiste noexiste noexiste noexiste noexiste noexiste",
    // 12 palabras válidas pero checksum incorrecto
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
  ];

  for (const caso of casos) {
    assert.throws(() => mnemonicToWallet(caso), /Mnemonic BIP-39 inválido/);
  }
});

test("mnemonicToWallet normaliza espacios y mayúsculas del mnemonic", () => {
  const base = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const conRuido = "  ABANDON   ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT  ";
  assert.equal(mnemonicToWallet(conRuido).address, mnemonicToWallet(base).address);
});

test("mnemonicToWallet rechaza passphrase que no sea texto", () => {
  const base = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  assert.throws(() => mnemonicToWallet(base, 123), /texto/);
});

test("la passphrase BIP-39 cambia la clave derivada", () => {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const sin = mnemonicToWallet(mnemonic);
  const con = mnemonicToWallet(mnemonic, "TREZOR");

  assert.notEqual(sin.privateKey, con.privateKey);
  assert.notEqual(sin.address, con.address);
  assert.equal(con.path, ETHEREUM_PATH);
});

// --------------------------------------------------------------- keystore

test("encryptV3 exige una frase de al menos 12 caracteres y de tipo texto", () => {
  assert.throws(() => encryptV3(PRIVATE_KEY, ""), KeystoreError);
  assert.throws(() => encryptV3(PRIVATE_KEY, "a".repeat(11)), KeystoreError);
  assert.throws(() => encryptV3(PRIVATE_KEY, null), KeystoreError);
  assert.equal(encryptV3(PRIVATE_KEY, "a".repeat(12)).version, 3);
});

test("decryptV3 rechaza entradas estructuralmente inválidas sin lanzar otra cosa", () => {
  const casos = [
    [null, PASSWORD],
    [{}, PASSWORD],
    [{ version: 2 }, PASSWORD],
    [{ version: 3 }, PASSWORD],
    [{ version: 3, crypto: {} }, PASSWORD],
    [{ version: 3, crypto: { kdf: "argon2" } }, PASSWORD],
    [{ version: 3, crypto: { kdf: "scrypt", cipher: "aes-256-gcm" } }, PASSWORD],
  ];

  for (const [keystore, password] of casos) {
    assert.throws(() => decryptV3(keystore, password), KeystoreError);
  }
});

test("decryptV3 rechaza una frase que no es texto", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  for (const bad of [undefined, null, 42, {}]) {
    assert.throws(() => decryptV3(keystore, bad), /Falta la frase/);
  }
});

test("decryptV3 rechaza parámetros scrypt fuera de rango", () => {
  const base = encryptV3(PRIVATE_KEY, PASSWORD);
  const mutaciones = [
    { n: 3 }, // no potencia de 2
    { n: 1 }, // por debajo del mínimo
    { n: 2 ** 21 }, // por encima del techo
    { r: 0 },
    { r: 64 },
    { p: 0 },
    { p: 16 },
    { dklen: 16 },
    { dklen: 128 },
  ];

  for (const cambio of mutaciones) {
    const keystore = structuredClone(base);
    Object.assign(keystore.crypto.kdfparams, cambio);
    assert.throws(() => decryptV3(keystore, PASSWORD), KeystoreError, JSON.stringify(cambio));
  }
});

test("decryptV3 rechaza campos hexadecimales de tamaño o formato inválido", () => {
  const base = encryptV3(PRIVATE_KEY, PASSWORD);
  const mutaciones = [
    ["ciphertext", "00"],
    ["ciphertext", "zz".repeat(32)],
    ["ciphertext", "0x" + "11".repeat(32) + "1"], // longitud impar
    ["mac", "00"],
    ["cipherparams", { iv: "00" }],
  ];

  for (const [campo, valor] of mutaciones) {
    const keystore = structuredClone(base);
    keystore.crypto[campo] = valor;
    assert.throws(() => decryptV3(keystore, PASSWORD), KeystoreError, `${campo}=${JSON.stringify(valor)}`);
  }
});

test("decryptV3 acepta un keystore PBKDF2-HMAC-SHA256 de geth", () => {
  const privateKey = Buffer.from(PRIVATE_KEY.slice(2), "hex");
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derivedKey = pbkdf2Sync(Buffer.from(PASSWORD, "utf8"), salt, 1000, 32, "sha256");
  const cipher = createCipheriv("aes-128-ctr", derivedKey.subarray(0, 16), iv);
  const ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  const mac = Buffer.from(keccak_256(concatBytes(derivedKey.subarray(16, 32), ciphertext)));

  const keystore = {
    version: 3,
    address: privateKeyToAddress(new Uint8Array(privateKey)).slice(2).toLowerCase(),
    crypto: {
      cipher: "aes-128-ctr",
      cipherparams: { iv: iv.toString("hex") },
      ciphertext: ciphertext.toString("hex"),
      kdf: "pbkdf2",
      kdfparams: { dklen: 32, salt: salt.toString("hex"), c: 1000, prf: "hmac-sha256" },
      mac: mac.toString("hex"),
    },
  };

  const descifrada = decryptV3(keystore, PASSWORD);
  assert.equal("0x" + Buffer.from(descifrada).toString("hex"), PRIVATE_KEY);
});

test("decryptV3 rechaza PBKDF2 con prf o iteraciones inválidas", () => {
  const base = encryptV3(PRIVATE_KEY, PASSWORD);
  const pb = structuredClone(base);
  pb.crypto.kdf = "pbkdf2";
  pb.crypto.kdfparams = { dklen: 32, salt: "00".repeat(32), c: 10, prf: "hmac-sha512" };

  assert.throws(() => decryptV3(pb, PASSWORD), KeystoreError);

  pb.crypto.kdfparams.c = 10_000_000;
  assert.throws(() => decryptV3(pb, PASSWORD), /c.*inválido/);
});

test("inspectKeystore no lanza con objetos incompletos", () => {
  for (const entrada of [null, {}, { crypto: {} }, { Crypto: { kdfparams: { N: 8192, kdf: "scrypt" } } }]) {
    assert.doesNotThrow(() => inspectKeystore(entrada));
  }
  assert.equal(inspectKeystore({ crypto: { kdfparams: { N: 8192 }, kdf: "scrypt" } }).n, 8192);
});

test("cifrar dos veces la misma clave produce sal, iv y ciphertext distintos", () => {
  const a = encryptV3(PRIVATE_KEY, PASSWORD);
  const b = encryptV3(PRIVATE_KEY, PASSWORD);

  assert.notEqual(a.crypto.kdfparams.salt, b.crypto.kdfparams.salt);
  assert.notEqual(a.crypto.cipherparams.iv, b.crypto.cipherparams.iv);
  assert.notEqual(a.crypto.ciphertext, b.crypto.ciphertext);
  assert.notEqual(a.id, b.id);
});

test("un keystore sin el campo address se descifra igual", () => {
  const keystore = encryptV3(PRIVATE_KEY, PASSWORD);
  delete keystore.address;
  assert.equal("0x" + Buffer.from(decryptV3(keystore, PASSWORD)).toString("hex"), PRIVATE_KEY);
});

test("roundtrip con varias claves aleatorias (scrypt es caro a propósito)", () => {
  for (let i = 0; i < 5; i++) {
    const key = randomPrivateKey();
    const hex = "0x" + Buffer.from(key).toString("hex");
    const keystore = encryptV3(hex, PASSWORD);
    const salida = "0x" + Buffer.from(decryptV3(keystore, PASSWORD)).toString("hex");
    assert.equal(salida, hex);
  }
});

// ------------------------------------------------------------ aleatoriedad

test("sin crypto.getRandomValues se lanza en vez de degradar a Math.random", () => {
  const original = globalThis.crypto;
  try {
    Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
    assert.throws(() => csprng(32), /crypto.getRandomValues/);
    assert.throws(() => randomPrivateKey(), /crypto.getRandomValues/);
  } finally {
    Object.defineProperty(globalThis, "crypto", { value: original, configurable: true });
  }
});

// ---------------------------------------------------------------- prompt

test("las preguntas de secretos exigen TTY", async () => {
  // En el runner de tests stdin no es una TTY: debe fallar, no colgarse.
  if (process.stdin.isTTY) return;

  // ask/askSecret validan la TTY antes de devolver la promesa.
  assert.throws(() => ask("x: "), /terminal interactiva/);
  assert.throws(() => askSecret("x: "), /terminal interactiva/);
  await assert.rejects(askPassphrase(), /terminal interactiva/);
});
