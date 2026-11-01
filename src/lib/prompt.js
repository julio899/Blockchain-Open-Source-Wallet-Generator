import readline from "node:readline";

const MIN_PASSPHRASE_LENGTH = 12;

export class PromptError extends Error {
  constructor(message) {
    super(message);
    this.name = "PromptError";
  }
}

/**
 * Un secreto solo se puede ocultar en una terminal real. Si stdin viene de un
 * pipe o de una redirección, el valor queda en el archivo o en el historial de
 * shell sin que el usuario lo note: mejor abortar.
 */
function requireTTY() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new PromptError(
      "Esta operación necesita una terminal interactiva (TTY). No se aceptan secretos por pipe."
    );
  }
}

// Una sola interfaz para todo el proceso: crear y cerrar una por pregunta
// pierde el estado del flujo de entrada (y con él, caracteres escritos).
let rl = null;

function getInterface() {
  requireTTY();
  if (rl) return rl;

  rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  rl.on("SIGINT", () => {
    process.stdout.write("\n");
    rl.close();
    process.exit(130);
  });

  return rl;
}

function question(text, { secret = false } = {}) {
  const iface = getInterface();
  const originalWrite = iface._writeToOutput.bind(iface);

  if (secret) {
    // La pregunta se escribe aparte; el echo de lo que se teclea se silencia.
    process.stdout.write(text);
    iface._writeToOutput = () => {};
  }

  return new Promise((resolve, reject) => {
    let settled = false;

    const onClose = () => {
      if (settled) return;
      settled = true;
      reject(new PromptError("La entrada se cerró antes de terminar."));
    };

    iface.once("close", onClose);

    iface.question(secret ? "" : text, (answer) => {
      if (settled) return;
      settled = true;
      iface.removeListener("close", onClose);

      if (secret) {
        iface._writeToOutput = originalWrite;
        process.stdout.write("\n");
      }
      resolve(answer);
    });
  });
}

/** Pregunta normal, con echo (direcciones, rutas). */
export function ask(text) {
  return question(text);
}

/** Pregunta de un secreto: no se muestra lo que se escribe. */
export function askSecret(text) {
  return question(text, { secret: true });
}

/**
 * Pide una frase de cifrado dos veces, sin echo, y exige una longitud mínima.
 * No se registra ni el valor ni su longitud exacta.
 */
export async function askPassphrase(text = "Frase de cifrado: ") {
  const first = await askSecret(text);
  const second = await askSecret("Confirme la frase: ");

  if (first !== second) {
    throw new PromptError("Las frases no coinciden.");
  }
  if (first.length < MIN_PASSPHRASE_LENGTH) {
    throw new PromptError(
      `La frase de cifrado debe tener al menos ${MIN_PASSPHRASE_LENGTH} caracteres.`
    );
  }
  if (first.trim().length === 0) {
    throw new PromptError("La frase de cifrado no puede estar vacía.");
  }
  return first;
}

/** Cierra la interfaz al terminar (permite que el proceso salga). */
export function closePrompt() {
  if (rl) {
    rl.close();
    rl = null;
  }
}
