# Seguridad

Este documento describe qué protege el generador, qué no protege, y cómo
verificar que lo que se ejecuta es lo que se revisó.

## Aviso importante sobre wallets creadas con la versión 1

La versión 1 de este proyecto **imprimía la clave privada y la frase de cifrado
en claro** en la terminal (`console.log({ wallet, fraseEncriptacionFijadaPorUsuario })`)
y generaba un **código QR de la clave privada**. Además, cifraba los keystores con
scrypt `N=8192`, un parámetro hoy 16 veces más débil que el recomendado.

Si creó o descifró una wallet con esa versión:

- Considere la clave privada **expuesta**. El scrollback de la terminal, los logs,
  las capturas de pantalla o cualquier grabación pueden contenerla.
- Recifrar el keystore **no deshace esa exposición**: use `npm run recifrar` para
  mejorar el archivo, pero lo correcto es **generar una wallet nueva y mover los
  fondos**.

## Modelo de amenaza

Protege contra:

- Aleatoriedad predecible: se usa `crypto.getRandomValues` (CSPRNG del sistema
  operativo) con rechazo de valores fuera de `[1, n-1]`. No hay `Math.random`.
- Fuerza bruta offline sobre el keystore: scrypt `N=2^17, r=8, p=1` (~128 MiB
  por intento) y salt aleatorio de 32 bytes por archivo.
- Manipulación del archivo cifrado: el MAC `keccak256(dk[16..32] || ciphertext)`
  se compara en tiempo constante y la dirección declarada debe coincidir con la
  derivada de la clave descifrada.
- Archivos hostiles: los parámetros KDF se validan antes de derivar (techo de
  memoria), se rechazan symlinks y archivos de más de 64 KiB, y la ruta se
  construye solo con una dirección validada (no hay path traversal).
- Lectura por otros usuarios del equipo: `wallets/` con modo `0700` y los
  keystores con `0600`, sin sobrescritura silenciosa.
- Dependencias con CVEs conocidos: árbol de 5 paquetes auditados y sin
  dependencias transitivas más allá de `@noble/*` y `@scure/base`; `web3`,
  `elliptic`, `crypto-browserify` y `uuid` ya no están.
- Ejecución remota en la web: el bundle es local, la CSP prohíbe toda conexión
  (`connect-src 'none'`) y `scripts/verify-bundle.js` falla si el bundle contiene
  URLs, `eval`, `innerHTML` o accesos a módulos de Node.

No protege contra:

- **Un equipo comprometido.** Keyloggers, malware, extensiones del navegador,
  pantallas compartidas o sesiones remotas ven todo lo que aparece en pantalla.
  Una wallet software no es una hardware wallet.
- **Contraseñas débiles.** scrypt encarece el ataque, no lo elimina. Use una
  frase larga y aleatoria (6 palabras diceware o 20+ caracteres).
- **Scrollback, portapapeles y capturas.** Un secreto mostrado en pantalla puede
  quedar en el historial del terminal o en una foto.
- **Borrado seguro en memoria.** JavaScript no permite borrar cadenas de forma
  fiable; `fill(0)` sobre los buffers propios es lo máximo posible. Pueden quedar
  copias en el recolector de basura, swap o volcados de núcleo.
- **Alojamiento de terceros.** La demo de GitHub Pages puede ser servida con un
  bundle distinto al publicado. Para operar con fondos reales, clone el
  repositorio, desconecte la red y abra `index.html` localmente.

## Uso recomendado

1. Descargue o clone el repositorio y verifique el commit.
2. `npm ci` (la instalación necesita red; la ejecución no).
3. `npm audit --omit=dev` debe dar 0 vulnerabilidades.
4. Desconecte la red. Opcionalmente, trabaje en un equipo dedicado o en un live USB.
5. Genere la wallet (`npm start` o `npm run build`) y guarde el respaldo en papel
   o en un medio offline.
6. Borre la pantalla (`clear`) y no comparta la salida.

Para evitar volcados de núcleo durante la sesión: `ulimit -c 0`.

## Verificación de integridad

```bash
npm ci
npm audit --omit=dev          # 0 vulnerabilidades
npm ls web3 elliptic          # vacío
npm test                      # vectores oficiales EIP-55, BIP-39, BIP-44
npm run build:web
node scripts/verify-bundle.js # imprime el sha256 del bundle y verifica que no hay red
```

El archivo `easy.qrcode.min.js` es la única librería vendorizada (no está en npm
como dependencia fija). Su hash actual es:

```
sha256  cac9e3e4ca7d69d473a57ca16c65b66137544a975aa628271f7679edb32ae86f
```

Si el hash cambia sin que se haya revisado el cambio, no abra la página.

## Detalles criptográficos

- **Entropía**: `crypto.getRandomValues(new Uint8Array(32))`, con rechazo si el
  escalar no está en `[1, n-1]` de secp256k1. Sin hash adicional ni reducción
  módulo `n` (evita sesgo).
- **Dirección**: `keccak256(pubkey[1..65])[12..32]` en formato EIP-55. Se usa
  `keccak_256` de `@noble/hashes`: el `sha3-256` de OpenSSL/Node es NIST SHA-3,
  **no** Keccak, y produce direcciones distintas.
- **BIP-39**: 24 palabras (256 bits), normalización NFKD, PBKDF2-HMAC-SHA512
  (2048 iteraciones).
- **BIP-44**: `m/44'/60'/0'/0/0`.
- **Keystore**: Web3 Secret Storage V3, `aes-128-ctr`, scrypt `N=2^17, r=8, p=1,
  dklen=32`, MAC con keccak256. Compatible con MetaMask y geth.

## Reportar una vulnerabilidad

Abra un issue privado en el repositorio o escriba al autor
(@julio899). No publique detalles explotables antes de que haya una corrección.
