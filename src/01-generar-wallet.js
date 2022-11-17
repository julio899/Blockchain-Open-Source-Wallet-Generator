const Web3 = require("web3");
const qrcode = require("qrcode-terminal"); // libreria para generar el Qr en el Terminal

// # creamos instancia para comunicación con la BlockChain
// # uso de funcionalidades regidas por estándares de la web3
// Estándares tanto en (Etherium, BSC, Polygon) y todas la Blockchain derivadas de ETH

const web3 = new Web3();

// llamamos al estándar de generación de Cuenta
// pasando una frase conocida como Entropía
// a partir de esta frase se genera aleatoriedad y genera
// una dirección y combinación ÚNICA
// (Refuerzo) preferiblemente genera una cadena de Texto sumamente larga y única que solo tú controles

/*
 * En mi caso género un número aleatorio entre 0 y 10.000.000 y lo paso a string (cadena de texto)
 * también genero una cadena de texto aleatoria con web.utils.randomHex(32)
 * y todo envuelto con sha3 (estándar de encriptación)
 */

const cadenaHexadecimalUnicaAleatorea = web3.utils.sha3(
	Math.random(0, 10000000).toString() + web3.utils.randomHex(32)
);

// Generacion de la Wallet
const wallet = web3.eth.accounts.create(cadenaHexadecimalUnicaAleatorea);

console.log({ wallet });

// Generacion de QR de la Wallet Address (Cartera)
qrcode.generate(wallet.address, { small: true }, function (qrcode) {
	console.log("Wallet Address");
	console.log(qrcode);
});

// Generacion de QR de la privateKey (LLave Privada)
qrcode.generate(wallet.privateKey, { small: true }, function (qrcode) {
	console.log("Private Key");
	console.log(qrcode);
});
