import {
  adminAuth,
  adminDb,
} from "../config/firebaseAdmin.js";

export async function verificarAdministrador(
  req,
  res,
  next
) {
  try {
    const encabezado =
      String(
        req.headers
          .authorization ||
          ""
      );

    if (
      !encabezado.startsWith(
        "Bearer "
      )
    ) {
      return res.status(
        401
      ).json({
        ok: false,
        message:
          "No se recibió una sesión administrativa válida.",
      });
    }

    const token =
      encabezado
        .slice(
          7
        )
        .trim();

    if (!token) {
      return res.status(
        401
      ).json({
        ok: false,
        message:
          "La sesión administrativa no es válida.",
      });
    }

    /*
     * checkRevoked = true:
     * si el administrador perdió su sesión o sus tokens
     * fueron revocados, esta API no acepta el token.
     */
    const decoded =
      await adminAuth
        .verifyIdToken(
          token,
          true
        );

    const perfilRef =
      adminDb
        .collection(
          "users"
        )
        .doc(
          decoded.uid
        );

    const perfilSnap =
      await perfilRef.get();

    if (
      !perfilSnap.exists
    ) {
      return res.status(
        403
      ).json({
        ok: false,
        message:
          "La cuenta autenticada no tiene un perfil de RiberGas.",
      });
    }

    const perfil =
      perfilSnap.data();

    if (
      perfil?.activo !==
      true
    ) {
      return res.status(
        403
      ).json({
        ok: false,
        message:
          "La cuenta administrativa está desactivada.",
      });
    }

    if (
      perfil
        ?.forzarCambioPassword ===
      true
    ) {
      return res.status(
        403
      ).json({
        ok: false,
        message:
          "Debe completar el cambio obligatorio de contraseña antes de utilizar funciones administrativas.",
      });
    }

    if (
      perfil?.rol !==
      "administrador"
    ) {
      return res.status(
        403
      ).json({
        ok: false,
        message:
          "Solo el rol Administrador puede restablecer contraseñas.",
      });
    }

    req.ribergasAdmin = {
      uid:
        decoded.uid,

      nombre:
        perfil.nombre ||
        perfil.usuario ||
        "Administrador",

      usuario:
        perfil.usuario ||
        "",

      rol:
        perfil.rol,
    };

    next();
  } catch (error) {
    console.error(
      "Error verificando administrador:",
      error
    );

    if (
      error?.code ===
        "auth/id-token-revoked" ||
      error?.code ===
        "auth/id-token-expired" ||
      error?.code ===
        "auth/argument-error"
    ) {
      return res.status(
        401
      ).json({
        ok: false,
        message:
          "La sesión administrativa venció. Vuelva a iniciar sesión.",
      });
    }

    return res.status(
      401
    ).json({
      ok: false,
      message:
        "No se pudo validar la sesión administrativa.",
    });
  }
}
