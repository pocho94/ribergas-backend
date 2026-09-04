import {
  readFile,
} from "node:fs/promises";

const ruta =
  process.argv[2];

if (!ruta) {
  console.error(
    "Uso: node scripts/convertir-service-account-base64.mjs ruta/al/serviceAccount.json"
  );

  process.exit(
    1
  );
}

const contenido =
  await readFile(
    ruta
  );

console.log(
  contenido.toString(
    "base64"
  )
);
