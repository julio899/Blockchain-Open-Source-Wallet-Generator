const Web3 = require("web3"); // libreria Web3
const qrcode = require("qrcode-terminal"); // libreria para generar el Qr en el Terminal
const prompt = require("prompt-sync")(); // libreria para solicitar entrada de datos del usuario desde la consola
const fs = require("fs"); // libreria para trabajar con archivos

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

// solicitamos la frase de encriptado
const fraseEncriptacionFijadaPorUsuario = prompt(
	"Ingrese si frase de encriptado para la serializacion de su llave:"
);

// simplemente para visualizarla en la consola
console.log({ wallet, fraseEncriptacionFijadaPorUsuario });

// Generacion de QR de la Wallet Address (Cartera)
qrcode.generate(wallet.address, { small: true }, function (qrcode) {
	console.log("\tWallet Address");
	console.log(qrcode);
});

// Generacion de QR de la privateKey (LLave Privada)
qrcode.generate(wallet.privateKey, { small: true }, function (qrcode) {
	console.log("\tPrivate Key");
	console.log(qrcode);
});

const privatedEncriptando = web3.eth.accounts.encrypt(
	wallet.privateKey,
	fraseEncriptacionFijadaPorUsuario
);

const desencriptando = web3.eth.accounts.decrypt(
	privatedEncriptando,
	fraseEncriptacionFijadaPorUsuario
);

(async () => {
	// si no existe el drectorio wallets se crea
	if (!fs.existsSync("wallets")) {
		fs.mkdirSync("wallets");
	}

	// Guardar en archivo de texto mi Wallet de forma encryptada writeFileSync appendFile
	await fs.writeFileSync(
		`wallets/${wallet.address}-encrypt.json`,
		JSON.stringify(privatedEncriptando, null, 2)
	);
})();
