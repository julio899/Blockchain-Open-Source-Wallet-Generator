import test from "node:test";
import assert from "node:assert/strict";
import {
  toChecksumAddress,
  privateKeyToAddress,
  privateKeyToWallet,
  normalizeAddress,
  isValidAddress,
} from "../src/lib/wallet.js";
import { generateMnemonic, mnemonicToWallet } from "../src/lib/mnemonic.js";
import { mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

// Vectores oficiales de EIP-55.
const EIP55_VECTORS = [
  "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
  "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
  "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
  "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
  "0x52908400098527886E0F7030069857D2E4169EE7",
  "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
  "0xde709f2102306220921060314715629080e2fb77",
  "0x27b1fdb04752bbc536007a920d24acb045561c26",
];

test("EIP-55: el checksum coincide con los vectores del estándar", () => {
  for (const expected of EIP55_VECTORS) {
    const lower = "0x" + expected.slice(2).toLowerCase();
    assert.equal(toChecksumAddress(lower), expected, `checksum de ${lower}`);
    assert.equal(toChecksumAddress(expected), expected, `idempotencia de ${expected}`);
  }
});

test("EIP-55: una dirección con un carácter cambiado no valida", () => {
  const good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
  const bad = good.slice(0, 5) + (good[5] === "b" ? "B" : "b") + good.slice(6);
  assert.notEqual(bad, good);
  assert.equal(isValidAddress(good), true);
  // Al cambiar la capitalización de un carácter el checksum deja de cuadrar.
  assert.equal(isValidAddress(bad), false);
});

test("clave privada conocida 0x…0001 → dirección conocida", () => {
  const privateKey = "0x" + "00".repeat(31) + "01";
  assert.equal(privateKeyToAddress(hexToBytes(privateKey.slice(2))), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

  const wallet = privateKeyToWallet(hexToBytes(privateKey.slice(2)));
  assert.equal(wallet.privateKey, privateKey);
  assert.equal(wallet.address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
});

test("claves privadas 0x…02 y 0x…03 → direcciones conocidas", () => {
  const derive = (n) => privateKeyToAddress(hexToBytes("00".repeat(31) + n));
  assert.equal(derive("02"), "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF");
  assert.equal(derive("03"), "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69");
});

test("BIP-39: vector oficial de Trezor (entropía 0x00…00)", () => {
  const mnemonic = generateMnemonicFromEntropy("00".repeat(16));
  assert.equal(
    mnemonic,
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  );
  assert.equal(
    bytesToHex(mnemonicToSeedSync(mnemonic, "TREZOR")),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
      "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  );
});

test("BIP-39: 256 bits de 0xff → 24 palabras terminadas en 'vote'", () => {
  const mnemonic = generateMnemonicFromEntropy("ff".repeat(32));
  const words = mnemonic.split(" ");
  assert.equal(words.length, 24);
  assert.equal(words.at(-1), "vote");
  assert.equal(words.slice(0, 23).every((w) => w === "zoo"), true);
});

test("BIP-44: mnemonic de prueba de Hardhat/Foundry deriva la cuenta 0", () => {
  const mnemonic = "test test test test test test test test test test test junk";
  const wallet = mnemonicToWallet(mnemonic);

  assert.equal(wallet.path, "m/44'/60'/0'/0/0");
  assert.equal(
    wallet.privateKey,
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  );
  assert.equal(wallet.address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
});

test("BIP-39: los mnemonic generados son válidos y de 24 palabras", () => {
  for (let i = 0; i < 20; i++) {
    const { mnemonic, words } = generateMnemonic(256);
    assert.equal(words, 24);
    assert.equal(mnemonic.split(" ").length, 24);
    assert.equal(mnemonicToWallet(mnemonic).address.startsWith("0x"), true);
  }
});

test("normalizeAddress rechaza entradas que no son direcciones", () => {
  for (const bad of ["", "0x", "../../etc/passwd", "0x1234", "javascript:alert(1)"]) {
    assert.throws(() => normalizeAddress(bad), /Dirección inválida/);
  }
  assert.equal(
    normalizeAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
    "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
  );
});

// entropyToMnemonic se usa a través de @scure/bip39 para fijar los vectores.
import { entropyToMnemonic } from "@scure/bip39";
function generateMnemonicFromEntropy(hex) {
  return entropyToMnemonic(hexToBytes(hex), wordlist);
}

test("BIP-39: vector oficial de 24 palabras con passphrase TREZOR", () => {
  const mnemonic = "abandon ".repeat(23).trim() + " art";
  assert.equal(
    bytesToHex(mnemonicToSeedSync(mnemonic, "TREZOR")),
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971" +
      "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
  );
});

test("BIP-44: 'abandon…about' deriva la dirección conocida de Ethereum", () => {
  const wallet = mnemonicToWallet(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  );
  assert.equal(
    wallet.privateKey,
    "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
  );
  assert.equal(wallet.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
});

test("BIP-39: un mnemonic con checksum alterado se rechaza", () => {
  assert.throws(
    () =>
      mnemonicToWallet(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
      ),
    /Mnemonic BIP-39 inválido/
  );
});
