import {
  applicationDefault,
  cert,
  getApps,
  initializeApp,
} from "firebase-admin/app";

import {
  getAuth,
} from "firebase-admin/auth";

import {
  getFirestore,
} from "firebase-admin/firestore";

function obtenerCredencial() {
  const base64 =
    String(
      process.env
        .FIREBASE_SERVICE_ACCOUNT_BASE64 ||
        ""
    ).trim();

  if (base64) {
    try {
      const json =
        Buffer.from(
          base64,
          "base64"
        ).toString(
          "utf8"
        );

      const cuenta =
        JSON.parse(
          json
        );

      return cert(
        cuenta
      );
    } catch (error) {
      console.error(
        "No se pudo leer FIREBASE_SERVICE_ACCOUNT_BASE64.",
        error
      );

      throw new Error(
        "La credencial administrativa de Firebase no es válida."
      );
    }
  }

  /*
   * Alternativa útil para servidores que ya proporcionan
   * Application Default Credentials.
   */
  return applicationDefault();
}

const app =
  getApps().length > 0
    ? getApps()[0]
    : initializeApp({
        credential:
          obtenerCredencial(),
      });

export const adminAuth =
  getAuth(
    app
  );

export const adminDb =
  getFirestore(
    app
  );
