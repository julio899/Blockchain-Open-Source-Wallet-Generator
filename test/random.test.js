import test from "node:test";
import assert from "node:assert/strict";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes, randomPrivateKey, curveOrder } from "../src/lib/random.js";
import { privateKeyToAddress, isValidAddress, toChecksumAddress } from "../src/lib/wallet.js";

test("randomPrivateKey devuelve claves en [1, n-1] y todas distintas", () => {
  const seen = new Set();
  const n = curveOrder();

  for (let i = 0; i < 5000; i++) {
    const key = randomPrivateKey();
    assert.equal(key.length, 32);
    assert.equal(key instanceof Uint8Array, true);

    const value = BigInt("0x" + Buffer.from(key).toString("hex"));
    assert.ok(value >= 1n && value < n, "la clave debe estar en el rango del grupo");
    assert.equal(secp256k1.utils.isValidSecretKey(key), true);

    seen.add(Buffer.from(key).toString("hex"));
  }

  assert.equal(seen.size, 5000, "no debe haber repeticiones en 5000 muestras");
});

test("las direcciones derivadas son válidas y llevan checksum EIP-55", () => {
  for (let i = 0; i < 200; i++) {
    const address = privateKeyToAddress(randomPrivateKey());
    assert.equal(isValidAddress(address), true);
    assert.equal(toChecksumAddress(address), address);
  }
});

test("randomBytes devuelve la longitud pedida y no repite", () => {
  const a = randomBytes(32);
  const b = randomBytes(32);
  assert.equal(a.length, 32);
  assert.notEqual(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"));
});
