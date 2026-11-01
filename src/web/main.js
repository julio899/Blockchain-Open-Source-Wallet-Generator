import { randomPrivateKey } from "../lib/random.js";
import { privateKeyToWallet } from "../lib/wallet.js";
import { generateMnemonicWallet } from "../lib/mnemonic.js";

/**
 * La generación en el navegador usa la misma librería que la CLI: el mismo
 * CSPRNG (crypto.getRandomValues), la misma derivación secp256k1/keccak y la
 * misma ruta BIP-44. No hay ninguna llamada de red: la página funciona offline.
 */

const $ = (selector) => document.querySelector(selector);

let current = null;

function clear(node) {
  node.replaceChildren();
}

function render(wallet, mnemonic) {
  current = wallet;

  $("#address").textContent = wallet.address;

  const mnemonicBlock = $("#mnemonic-block");
  if (mnemonic) {
    $("#mnemonic").textContent = mnemonic;
    mnemonicBlock.hidden = false;
  } else {
    mnemonicBlock.hidden = true;
    $("#mnemonic").textContent = "";
  }

  // La clave privada queda oculta hasta que el usuario la pida explícitamente.
  $("#secret-block").hidden = true;
  $("#private-key").textContent = "";
  clear($("#qr-private-key"));

  clear($("#qr-address"));
  new window.QRCode($("#qr-address"), {
    text: wallet.address,
    colorDark: "#004f05",
    colorLight: "transparent",
  });
}

function revealSecret() {
  if (!current) return;

  $("#private-key").textContent = current.privateKey;
  clear($("#qr-private-key"));
  new window.QRCode($("#qr-private-key"), {
    text: current.privateKey,
    colorDark: "#ff2e00",
    colorLight: "transparent",
  });
  $("#secret-block").hidden = false;
  $("#secret-warning").textContent =
    "Clave privada visible en pantalla: no la fotografíe ni la comparta. Quien la tenga controla los fondos.";
}

function generateRandom() {
  render(privateKeyToWallet(randomPrivateKey()), null);
}

function generateFromMnemonic() {
  const wallet = generateMnemonicWallet();
  render(wallet, wallet.mnemonic);
}

window.addEventListener("DOMContentLoaded", () => {
  $("#btn-random").addEventListener("click", generateRandom);
  $("#btn-mnemonic").addEventListener("click", generateFromMnemonic);
  $("#btn-reveal").addEventListener("click", revealSecret);

  generateRandom();
});
