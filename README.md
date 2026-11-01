# Blockchain Open Source Wallet Generator

Generador de wallets Ethereum **100 % offline** en el que tú controlas las claves.
Crea una clave privada aleatoria o un mnemonic BIP-39 de 24 palabras, deriva la
dirección con checksum EIP-55 y, si quieres, guarda la clave cifrada en un keystore
compatible con MetaMask y geth.

No hay servidor, no hay telemetría, no hay cuenta de usuario y no se guarda nada.
La página web carga un único bundle local y su política de seguridad prohíbe toda
conexión de red.

> **¿Vienes de la versión 1?** Ese código imprimía la clave privada y la frase de
> cifrado en claro y usaba scrypt `N=8192`. Esas wallets deben considerarse
> expuestas: lee [SECURITY.md](SECURITY.md) antes de reutilizarlas.

---

## Índice

- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Inicio rápido](#inicio-rápido)
- [Cookbook](#cookbook)
  - [1. Wallet desechable de un solo uso](#1-wallet-desechable-de-un-solo-uso)
  - [2. Wallet respaldada con mnemonic de 24 palabras](#2-wallet-respaldada-con-mnemonic-de-24-palabras)
  - [3. Guardar la clave cifrada en disco](#3-guardar-la-clave-cifrada-en-disco)
  - [4. Importar el keystore en MetaMask](#4-importar-el-keystore-en-metamask)
  - [5. Recuperar la clave desde el keystore](#5-recuperar-la-clave-desde-el-keystore)
  - [6. Recuperar la clave desde el mnemonic](#6-recuperar-la-clave-desde-el-mnemonic)
  - [7. Migrar un keystore de la versión 1](#7-migrar-un-keystore-de-la-versión-1)
  - [8. Generar en un equipo aislado (air-gapped)](#8-generar-en-un-equipo-aislado-air-gapped)
  - [9. Comprobar que una clave corresponde a una dirección](#9-comprobar-que-una-clave-corresponde-a-una-dirección)
  - [10. Usar la interfaz web sin conexión](#10-usar-la-interfaz-web-sin-conexión)
- [Tips de seguridad](#tips-de-seguridad)
- [Elegir la frase de cifrado](#elegir-la-frase-de-cifrado)
- [Problemas frecuentes](#problemas-frecuentes)
- [Referencia de comandos](#referencia-de-comandos)
- [Cómo funciona](#cómo-funciona)
- [Tests y verificación](#tests-y-verificación)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Licencia](#licencia)

---

## Requisitos

- **Node.js 20.19 o superior** (probado en 20, 22, 24 y 26).
- La instalación necesita red; **la generación de wallets no**.

## Instalación

```bash
git clone https://github.com/julio899/Blockchain-Open-Source-Wallet-Generator.git
cd Blockchain-Open-Source-Wallet-Generator
npm ci
```

Verifica la instalación antes de usarla con fondos reales:

```bash
npm audit --omit=dev   # debe decir: found 0 vulnerabilities
npm test               # vectores oficiales y casos límite
```

## Inicio rápido

```bash
npm start
```

Salida:

```
Dirección : 0x52e53df26dE2c15Fcf3f81F0639d91CDAd5a165C
Clave priv: 0x8ff411321e6b1cf3d5beff33f2a795e171e47b88875a841e8cf60d74f62f4664

        Dirección
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█ ▄▄▄▄▄ █   █▄ █▄█▄▀▀ █ ▄▄▄▄▄ █
...
```

El QR que se muestra es el de la **dirección**, que es pública. El de la clave
privada solo aparece si lo pides con `--qr-key`, porque una imagen de la clave se
puede fotografiar.

---

## Cookbook

### 1. Wallet desechable de un solo uso

Para una cuenta temporal, una prueba o recibir un pago que moverás enseguida.

```bash
npm start
```

Anota la dirección, mueve los fondos y descarta la clave. No hay recuperación: si
pierdes la clave, pierdes los fondos.

> No uses `npm start` con `tee`, `> archivo` o grabando la sesión: la clave privada
> quedaría escrita en el disco.

### 2. Wallet respaldada con mnemonic de 24 palabras

El mnemonic es el respaldo de verdad: 256 bits de entropía, con checksum, y se puede
restaurar en casi cualquier wallet del ecosistema.

```bash
node src/cli/01-generar-wallet.js --mnemonic
```

Salida:

```
Mnemonic BIP-39 (guárdelo offline, es el respaldo de la wallet):
  police gap dish cart bitter erase mom patient weird scorpion tide pill volcano
  tube nose quantum absorb essay whale ugly depend trim copper possible

Ruta de derivación: m/44'/60'/0'/0/0
Dirección : 0x2aeb33B7f0Fa20e2168fC256551F34D21563C376
Clave priv: 0xf92ac1af8b443734ee2d1be830adece76541a591e7381d0d50b0b7a29031bb81
```

Tips:

- Copia las 24 palabras **en papel**, en orden, a mano. No a un archivo, no a una
  foto, no a un gestor de notas en la nube.
- Lee el mnemonic en voz baja una vez: si una palabra te suena rara, es que has
  copiado mal (el checksum lo detectaría al restaurar).
- La ruta `m/44'/60'/0'/0/0` es la cuenta 0 estándar de Ethereum. MetaMask, Ledger
  y Trezor usan la misma, así que la dirección coincide al restaurar.
- Si usas una *passphrase* BIP-39 (la "25ª palabra"), la necesitas **junto** al
  mnemonic. Sin ella la dirección es otra y los fondos no aparecen.

### 3. Guardar la clave cifrada en disco

```bash
npm run build                 # wallet aleatoria
npm run build -- --mnemonic   # wallet derivada de BIP-39
```

El programa pide la frase de cifrado dos veces, sin mostrar lo que escribes:

```
Frase de cifrado:
Confirme la frase:

Dirección : 0x9AF297B1197EB246C098C81FBf9f90412a885a63
Archivo   : wallets/0x9af297b1197eb246c098c81fbf9f90412a885a63-encrypt.json
```

El archivo queda con permisos `0600` dentro de `wallets/` (`0700`) y es un keystore
Web3 Secret Storage V3 con scrypt `N=2^17`. Por diseño **no se sobrescribe**: si el
archivo existe, el programa se detiene.

Tips:

- Copia `wallets/` a un USB o a un medio **offline** y borra la copia del equipo.
- La frase de cifrado no se guarda en ningún sitio. Si la pierdes, el archivo es
  irrecuperable.
- `wallets/` está en `.gitignore`: comprueba dos veces antes de subir nada a un
  repositorio.

### 4. Importar el keystore en MetaMask

1. MetaMask → menú de cuentas → **Importar cuenta**.
2. Elige **JSON** y selecciona `wallets/<dirección>-encrypt.json`.
3. Escribe la misma frase de cifrado.
4. La dirección importada debe coincidir exactamente con la que mostró el programa.

Si MetaMask muestra otra dirección, no importes: detente y revisa que no hayas
cambiado el archivo.

### 5. Recuperar la clave desde el keystore

```bash
npm run desencriptar
```

Pide la dirección y la frase (sin echo) y muestra la clave privada.

- Acepta los keystores antiguos con `N=8192` y avisa de que son débiles.
- El error es genérico a propósito: "frase incorrecta o archivo dañado" no revela
  cuál de las dos cosas falló.
- Sala de emergencias: si la frase es correcta, la dirección del archivo debe
  coincidir con la derivada; si no coincide, el archivo fue manipulado.

### 6. Recuperar la clave desde el mnemonic

No hace falta este proyecto para eso, pero sirve para comprobar que tu copia en
papel es correcta sin exponerla en un servicio externo:

```bash
node src/cli/01-generar-wallet.js --help
# y en tus propias herramientas: BIP-39 -> PBKDF2-SHA512 -> BIP-32 m/44'/60'/0'/0/0
```

Regla práctica: si restauras el mnemonic y obtienes **la misma dirección**, la copia
está bien. Si obtienes otra, has copiado mal una palabra o te falta la passphrase
BIP-39.

### 7. Migrar un keystore de la versión 1

La versión 1 cifraba con scrypt `N=8192` (16 veces más barato de atacar).

```bash
npm run recifrar
```

1. Pide la dirección y la frase actual.
2. Pide la frase nueva, dos veces.
3. Escribe `wallets/<dirección>-recifrado-encrypt.json` **sin borrar el original**.
4. Imprime los dos comandos `mv` exactos para sustituir el archivo cuando hayas
   comprobado que el nuevo abre bien.

Importante: recifrar arregla el archivo, **no** la exposición. Si la clave o la
frase aparecieron en logs, QR o capturas, genera una wallet nueva y mueve los fondos.

### 8. Generar en un equipo aislado (air-gapped)

El escenario más seguro que permite este software:

1. Descarga el repositorio en un equipo sin red (o desconéctalo antes del paso 3).
2. `npm ci` (esto sí necesita red; si el equipo está aislado, instala en otro sitio
   y copia `node_modules/`).
3. `ulimit -c 0` para no dejar volcados de núcleo con la clave en memoria.
4. Genera la wallet y transcribe el respaldo a papel.
5. `clear` para borrar la pantalla antes de reconectar.

Nunca transfieras una clave privada por chat, correo, SMS o gestor de contraseñas.
Si necesitas moverla, muévela con el keystore cifrado.

### 9. Comprobar que una clave corresponde a una dirección

Antes de depositar fondos en una wallet generada en otro lado, confirma que la
clave y la dirección se corresponden:

```bash
node --input-type=module -e "
import { privateKeyToAddress, normalizePrivateKey } from './src/lib/wallet.js';
const clave = process.argv[1];
console.log(privateKeyToAddress(normalizePrivateKey(clave)));
" '0xTU_CLAVE_PRIVADA'
```

La salida debe ser la dirección que esperas. Si no coincide, no deposites.

### 10. Usar la interfaz web sin conexión

```bash
npm run build:web
node scripts/verify-bundle.js   # imprime el sha256 y verifica que no hay red
```

Abre `index.html` en el navegador, idealmente con la red desconectada.

- La página no hace ninguna petición: la CSP lo bloquea (`connect-src 'none'`).
- El bundle se genera desde el mismo `src/lib/` que la CLI, no desde un CDN.
- La clave privada está oculta hasta que pulsas **Mostrar clave privada**.

La demo de GitHub Pages se despliega con GitHub Actions (*Settings → Pages →
Source: GitHub Actions*). Aun así, para fondos reales usa la copia local: un
servidor de terceros siempre puede servir un bundle distinto.

---

## Tips de seguridad

| Haz | No hagas |
|---|---|
| Genera en un equipo de confianza, idealmente sin red | No generes en un cibercafé, una máquina compartida o una sesión remota |
| Guarda el respaldo en papel o en un medio offline, y prueba a restaurarlo | No guardes claves en notas, correo, capturas o gestores en la nube |
| Escribe la frase de cifrado a mano y guárdala aparte del keystore | No reutilices la frase del keystore como contraseña de otros servicios |
| Deposita primero una cantidad pequeña y mueve los fondos | No muevas todo el capital a una wallet recién generada sin probarla |
| Verifica la dirección en la pantalla del dispositivo al recibir fondos | No confíes en la dirección del portapapeles: malware la sustituye |
| Comprueba `npm audit` y el hash del bundle antes de usar | No ejecutes versiones modificadas ni bundles de origen desconocido |

Reglas de oro:

1. **La clave privada es el dinero.** Quien la tiene, cobra.
2. **El mnemonic es la clave privada en palabras.** Misma protección.
3. **La dirección es pública.** Compartirla es normal y necesario para recibir.
4. **No hay botón de deshacer.** Una transacción enviada no se cancela.
5. **Una wallet software no es una hardware wallet.** Si el equipo está comprometido,
   la clave está comprometida.

## Elegir la frase de cifrado

- Mínimo exigido: 12 caracteres. Recomendado: **6 palabras aleatorias** (diceware)
  o 20+ caracteres.
- scrypt `N=2^17` encarece la fuerza bruta, pero no convierte una frase débil en
  fuerte. `123456789012` cumple la longitud y es pésima.
- La frase y el keystore deben guardarse **separados**: juntos son un solo punto de
  fallo.
- Los espacios cuentan y no se recortan. Una mayúscula o un espacio de más = no
  descifra.

## Problemas frecuentes

| Mensaje / síntoma | Causa | Solución |
|---|---|---|
| `Esta operación necesita una terminal interactiva (TTY)` | Se ejecutó por pipe, cron o dentro de otro programa | Ejecútalo en una terminal real: `npm run build` |
| `Frase incorrecta o archivo dañado (el MAC no coincide)` | Frase distinta o archivo editado | Revisa mayúsculas y espacios; restaura desde una copia |
| `El checksum EIP-55 de la dirección no es válido` | Un carácter cambiado al copiar la dirección | Copia la dirección de nuevo desde la salida original |
| `Ya existe wallets/…-encrypt.json` | Ya hay un keystore con esa dirección | Muévelo antes; el programa nunca sobrescribe |
| `La dirección del keystore no coincide con la clave descifrada` | Archivo manipulado o mezclado | Descarta el archivo y restaura desde el respaldo |
| `No se encontró …-encrypt.json en wallets/` | Ruta de trabajo distinta | Ejecuta desde la raíz del proyecto |
| `KDF no soportado` / `Cifrado no soportado` | Keystore de otro formato | Usa MetaMask o geth para exportarlo de nuevo |
| Aviso de parámetros débiles | Keystore de la versión 1 (`N=8192`) | `npm run recifrar` y valora migrar fondos |

## Referencia de comandos

| Comando | Qué hace | Escribe en disco |
|---|---|---|
| `npm start` | Wallet aleatoria, dirección + clave + QR de la dirección | No |
| `npm start -- --mnemonic` | Igual, derivada de BIP-39 de 24 palabras | No |
| `npm start -- --qr-key` | Añade el QR de la clave privada | No |
| `npm run build` | Wallet aleatoria cifrada en `wallets/` | Sí (`0600`) |
| `npm run build -- --mnemonic` | Wallet BIP-39 cifrada en `wallets/` | Sí (`0600`) |
| `npm run desencriptar` | Descifra un keystore y muestra la clave | No |
| `npm run recifrar` | Recifra un keystore débil con `N=2^17` | Sí (archivo nuevo) |
| `npm run build:web` | Genera `dist/wallet.bundle.js` | Sí |
| `node scripts/verify-bundle.js` | Hash y comprobación de seguridad del bundle | No |
| `npm test` | Suite completa (una vez, más casos límite) | Temporal |
| `npm run audit` | `npm audit` de dependencias de producción | No |

Todas las CLI aceptan `--help`.

## Cómo funciona

- **Entropía**: `crypto.getRandomValues(new Uint8Array(32))`, con rechazo si el
  escalar no está en `[1, n-1]` de secp256k1. Sin `Math.random`, sin hash extra,
  sin reducción módulo `n`.
- **Dirección**: `keccak256(pubkey[1..65])[12..32]` en formato EIP-55. Se usa
  Keccak-256 real; el `sha3-256` de OpenSSL es NIST SHA-3 y da otra dirección.
- **BIP-39**: 24 palabras (256 bits), NFKD, PBKDF2-HMAC-SHA512 (2048 iteraciones).
- **BIP-44**: `m/44'/60'/0'/0/0`.
- **Keystore**: V3, `aes-128-ctr`, scrypt `N=2^17, r=8, p=1, dklen=32`,
  `mac = keccak256(dk[16..32] ‖ ciphertext)` verificado en tiempo constante.
- **Dependencias**: cinco, todas auditadas y sin dependencias transitivas más allá
  de `@noble/*` y `@scure/base`. Todo lo demás es runtime nativo de Node.

## Tests y verificación

```bash
npm test
```

La suite cubre, además del camino feliz:

- Vectores oficiales EIP-55 (8), BIP-39 de Trezor (128 y 256 bits), BIP-44 de
  Hardhat/Foundry y `abandon…about`.
- Rangos inválidos de clave privada (cero, `n`, mayor que `n`, longitudes y tipos).
- Direcciones mal formadas, checksum alterado, entradas que no son texto.
- Keystores incompletos, versión incorrecta, KDF y cifrado no soportados, `n` no
  potencia de dos, `r`/`p`/`dklen` fuera de rango, IV y MAC de tamaño incorrecto.
- MAC manipulado, dirección declarada distinta, `Crypto` en mayúscula, PBKDF2 de
  geth, y parámetros hostiles que intentarían agotar la memoria.
- Compatibilidad con scrypt `N=8192` de la versión 1.
- Permisos `0600`/`0700`, no sobrescritura, symlinks, JSON corrupto, archivos
  demasiado grandes y path traversal.
- CLI: `--help`, salida de los dos modos, y negativa a leer secretos sin TTY.

Verificación de dependencias y bundle:

```bash
npm audit --omit=dev
npm ls web3 elliptic
npm run build:web && node scripts/verify-bundle.js
```

## Estructura del proyecto

```
src/lib/      biblioteca criptográfica compartida entre CLI y web
  random.js     CSPRNG + rechazo fuera de rango
  wallet.js     secp256k1, keccak256, dirección EIP-55
  mnemonic.js   BIP-39 / BIP-32 / BIP-44
  keystore.js   cifrado y descifrado V3
  prompt.js     entrada oculta por terminal
  storage.js    archivos wallets/ con permisos y validación de rutas
src/cli/      comandos 01–04
src/web/      entrada del bundle del navegador
scripts/      build del bundle y verificación
test/         suite con node:test
```

## Licencia

Esta obra está bajo la licencia
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) (GENERAL PUBLIC LICENSE).
Distribuir libremente de forma GRATUITA: libertad de usar, estudiar, compartir
(copiar) y modificar el software.

## Autor

Julio Vinachi — [@julio899](https://twitter.com/julio899)

Mini guía en YouTube: https://www.youtube.com/watch?v=E12dJYvvJ4Y

Si desea realizar alguna donación de forma desinteresada para contribuir a la
creación de contenido open source de este tipo:
**0XA6C6235ED8C18DD15105CEBAE87228D9670E1974**
