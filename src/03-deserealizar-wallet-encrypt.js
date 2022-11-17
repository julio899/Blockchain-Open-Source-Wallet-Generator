const Web3 = require("web3"); // libreria Web3
const qrcode = require("qrcode-terminal"); // libreria para generar el Qr en el Terminal
const prompt = require("prompt-sync")(); // libreria para solicitar entrada de datos del usuario desde la consola
const fs = require("fs"); // libreria para trabajar con archivos

const web3 = new Web3();

// solicitamos la address del wallet a deserealizar
const walletAddress = prompt("Ingrese la wallet a deserealizar:");

// solicitamos la frase de encriptado
const fraseEncriptacionFijadaPorUsuario = prompt(
	"Ingrese frase de desencriptado:"
);

return (async () => {
	const fileLocation = `wallets/${walletAddress}-encrypt.json`;
	// r (read  solo lectura)
	fs.open(fileLocation, "r", function async(err, f) {
		// si existe el archivo y si no hay error continuamos con la lectura
		if (!err) {
			const privatedEncriptando = JSON.parse(
				fs.readFileSync(fileLocation, "utf8")
			);

			try {
				const desencriptando = web3.eth.accounts.decrypt(
					privatedEncriptando,
					fraseEncriptacionFijadaPorUsuario
				);

				console.log({ privatedEncriptando, desencriptando });

				// Generacion de QR de la privateKey (llave privada)
				qrcode.generate(desencriptando.privateKey, { small: true }, function (qrcode) {
					console.log("\t   Private Key");
					console.log(qrcode);
				});

			} catch (e) {
				// en caso de error se imprime el mensaje de error
				console.log(`${e.name}: ${e.message}`);
			}
		} else {
			// en caso que no se encuentre el archivo se imprime el mensaje de error
			console.log(`${err.name}: ${err.message}`);
		}
	});
})();
