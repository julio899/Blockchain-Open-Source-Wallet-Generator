import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function run(args, { cwd = root, input = "" } = {}) {
  return spawnSync(process.execPath, args, {
    cwd,
    input,
    encoding: "utf8",
    timeout: 30_000,
  });
}

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "wallet-cli-"));
}

test("01 --help explica las opciones y sale con 0", () => {
  const { status, stdout } = run(["src/cli/01-generar-wallet.js", "--help"]);

  assert.equal(status, 0);
  assert.match(stdout, /Uso: node src\/cli\/01-generar-wallet\.js/);
  assert.match(stdout, /--mnemonic/);
  assert.match(stdout, /--qr-key/);
});

test("01 genera una wallet aleatoria con dirección EIP-55 y clave de 32 bytes", () => {
  const { status, stdout } = run(["src/cli/01-generar-wallet.js"]);

  assert.equal(status, 0);
  const address = stdout.match(/Dirección : (0x[0-9a-fA-F]{40})/);
  const privKey = stdout.match(/Clave priv: (0x[0-9a-f]{64})/);

  assert.ok(address, "debe imprimir la dirección");
  assert.ok(privKey, "debe imprimir la clave privada");
  assert.match(address[1], /[A-F]/, "la dirección debe llevar checksum en mayúsculas");
  assert.equal(privKey[1].length, 66);
});

test("01 --mnemonic imprime 24 palabras y la ruta BIP-44", () => {
  const { status, stdout } = run(["src/cli/01-generar-wallet.js", "--mnemonic"]);

  assert.equal(status, 0);
  assert.match(stdout, /m\/44'\/60'\/0'\/0\/0/);

  const linea = stdout.split("\n").find((l) => l.trim().split(" ").length === 24);
  assert.ok(linea, "debe imprimir un mnemonic de 24 palabras");
});

test("01 no muestra el QR de la clave privada sin --qr-key", () => {
  const { stdout } = run(["src/cli/01-generar-wallet.js"]);
  assert.equal(stdout.includes("Clave privada (no fotografiar"), false);
});

test("02 y 03 se niegan a leer secretos por pipe (sin TTY)", () => {
  const cwd = tempDir();

  for (const script of [
    "src/cli/02-generar-wallet-con-encryptado.js",
    "src/cli/03-deserealizar-wallet-encrypt.js",
    "src/cli/04-recifrar-keystore.js",
  ]) {
    const { status, stdout, stderr } = run([path.join(root, script)], {
      cwd,
      input: "frase-que-no-debe-leerse\n",
    });

    assert.equal(status, 1, `${script} debe fallar sin TTY`);
    assert.match(stdout + stderr, /terminal interactiva/, `${script} debe explicar por qué`);
  }

  assert.deepEqual(fs.readdirSync(cwd), [], "no debe haber escrito archivos");
});

test("04 rechaza una dirección inválida antes de tocar el disco", () => {
  const cwd = tempDir();
  const { status, stdout, stderr } = run([path.join(root, "src/cli/04-recifrar-keystore.js")], {
    cwd,
    input: "../../etc/passwd\n",
  });

  assert.equal(status, 1);
  assert.match(stdout + stderr, /terminal interactiva|Dirección inválida/);
});
