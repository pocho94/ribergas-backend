import {
  Router,
} from "express";

import {
  FieldValue,
} from "firebase-admin/firestore";

import {
  adminAuth,
  adminDb,
} from "../config/firebaseAdmin.js";

import {
  verificarAdministrador,
} from "../middleware/verificarAdministrador.js";

import {
  validarPasswordTemporal,
} from "../utils/password.js";

const router =
  Router();

const ROLES_RESTABLECIBLES =
  new Set([
    "administradora",
    "duena",
  ]);

function tienePropiedad(
  objeto,
  propiedad
) {
  return Object.prototype
    .hasOwnProperty.call(
      objeto,
      propiedad
    );
}

async function restaurarBandera({
  referencia,
  anterior,
}) {
  const restauracion = {
    actualizadoEn:
      FieldValue
        .serverTimestamp(),
  };

  if (
    tienePropiedad(
      anterior,
      "forzarCambioPassword"
    )
  ) {
    restauracion
      .forzarCambioPassword =
      anterior
        .forzarCambioPassword;
  } else {
    restauracion
      .forzarCambioPassword =
      FieldValue.delete();
  }

  if (
    tienePropiedad(
      anterior,
      "passwordTemporalDesde"
    )
  ) {
    restauracion
      .passwordTemporalDesde =
      anterior
        .passwordTemporalDesde;
  } else {
    restauracion
      .passwordTemporalDesde =
      FieldValue.delete();
  }

  await referencia.update(
    restauracion
  );
}

router.post(
  "/restablecer-password",

  verificarAdministrador,

  async (
    req,
    res
  ) => {
    const administrador =
      req.ribergasAdmin;

    const uid =
      String(
        req.body?.uid ||
        ""
      ).trim();

    const passwordTemporal =
      req.body
        ?.passwordTemporal;

    if (!uid) {
      return res.status(
        400
      ).json({
        ok: false,
        message:
          "No se recibió el usuario que se desea restablecer.",
      });
    }

    if (
      uid ===
      administrador.uid
    ) {
      return res.status(
        400
      ).json({
        ok: false,
        message:
          "El Administrador debe cambiar su propia contraseña desde Configuración.",
      });
    }

    const validacion =
      validarPasswordTemporal(
        passwordTemporal
      );

    if (
      !validacion.valido
    ) {
      return res.status(
        400
      ).json({
        ok: false,
        message:
          validacion.mensaje,
      });
    }

    const usuarioRef =
      adminDb
        .collection(
          "users"
        )
        .doc(
          uid
        );

    let usuarioAnterior =
      null;

    let banderaPreparada =
      false;

    let passwordActualizada =
      false;

    try {
      const usuarioSnap =
        await usuarioRef.get();

      if (
        !usuarioSnap.exists
      ) {
        return res.status(
          404
        ).json({
          ok: false,
          message:
            "El usuario indicado no existe en RiberGas.",
        });
      }

      usuarioAnterior =
        usuarioSnap.data();

      if (
        !ROLES_RESTABLECIBLES
          .has(
            usuarioAnterior
              ?.rol
          )
      ) {
        return res.status(
          403
        ).json({
          ok: false,
          message:
            "Solo pueden restablecerse cuentas con rol Administradora o Dueña.",
        });
      }

      /*
       * Primero dejamos preparada la bandera de seguridad.
       * Si Firebase Auth rechaza el cambio de contraseña,
       * se intenta restaurar este estado.
       */
      await usuarioRef.update({
        forzarCambioPassword:
          true,

        passwordTemporalDesde:
          FieldValue
            .serverTimestamp(),

        actualizadoEn:
          FieldValue
            .serverTimestamp(),
      });

      banderaPreparada =
        true;

      /*
       * Cambio real en Firebase Authentication.
       * Esta operación solo existe en el backend:
       * nunca se exponen credenciales Admin al navegador.
       */
      await adminAuth.updateUser(
        uid,
        {
          password:
            passwordTemporal,
        }
      );

      passwordActualizada =
        true;

      let sesionesRevocadas =
        true;

      let advertencia =
        "";

      try {
        await adminAuth
          .revokeRefreshTokens(
            uid
          );
      } catch (errorRevocacion) {
        sesionesRevocadas =
          false;

        advertencia =
          "La contraseña se cambió, pero no se pudo confirmar la revocación adicional de todas las sesiones. La usuaria debe cerrar cualquier sesión anterior.";

        console.error(
          "No se pudieron revocar tokens:",
          errorRevocacion
        );
      }

      /*
       * Auditoría sin contraseñas.
       *
       * Si la auditoría falla, NO devolvemos un error de
       * restablecimiento, porque la contraseña ya fue
       * modificada en Firebase Authentication. En su lugar
       * devolvemos una advertencia clara al Administrador.
       */
      let auditoriaRegistrada =
        true;

      try {
        await adminDb
          .collection(
            "auditoria"
          )
          .add({
            modulo:
              "Usuarios",

            accion:
              "RESTABLECER_PASSWORD_USUARIO",

            descripcion:
              `Se restableció administrativamente la contraseña de ${usuarioAnterior.usuario || usuarioAnterior.nombre || uid}.`,

            entidadId:
              uid,

            datosAntes: {
              rol:
                usuarioAnterior.rol ||
                "",

              activo:
                usuarioAnterior.activo !==
                false,

              forzarCambioPassword:
                usuarioAnterior
                  .forzarCambioPassword ===
                true,
            },

            datosDespues: {
              rol:
                usuarioAnterior.rol ||
                "",

              activo:
                usuarioAnterior.activo !==
                false,

              forzarCambioPassword:
                true,

              sesionesRevocadas,
            },

            registradoPor: {
              uid:
                administrador.uid,

              nombre:
                administrador.nombre,

              usuario:
                administrador.usuario,

              rol:
                administrador.rol,
            },

            creadoEn:
              FieldValue
                .serverTimestamp(),
          });
      } catch (
        errorAuditoria
      ) {
        auditoriaRegistrada =
          false;

        console.error(
          "La contraseña fue restablecida, pero falló la auditoría:",
          errorAuditoria
        );

        advertencia =
          [
            advertencia,
            "El restablecimiento fue realizado, pero no se pudo registrar la auditoría. Revise el backend.",
          ]
            .filter(
              Boolean
            )
            .join(
              " "
            );
      }

      return res.status(
        200
      ).json({
        ok: true,

        uid,

        forzarCambioPassword:
          true,

        sesionesRevocadas,

        auditoriaRegistrada,

        warning:
          advertencia,
      });
    } catch (error) {
      console.error(
        "Error restableciendo contraseña:",
        error
      );

      /*
       * Si el fallo ocurrió antes del cambio de Auth o
       * durante él, intentamos no dejar una cuenta
       * marcada incorrectamente como temporal.
       *
       * Si updateUser ya alcanzó a ejecutarse y el fallo
       * fue posterior (p. ej. auditoría), la respuesta
       * seguirá siendo tratada cuidadosamente abajo.
       */
      if (
        banderaPreparada &&
        !passwordActualizada &&
        usuarioAnterior
      ) {
        try {
          await restaurarBandera({
            referencia:
              usuarioRef,

            anterior:
              usuarioAnterior,
          });
        } catch (
          rollbackError
        ) {
          console.error(
            "No se pudo restaurar la bandera de contraseña:",
            rollbackError
          );
        }
      }

      if (
        error?.code ===
        "auth/user-not-found"
      ) {
        return res.status(
          404
        ).json({
          ok: false,
          message:
            "La cuenta existe en Firestore, pero no existe en Firebase Authentication.",
        });
      }

      if (
        error?.code ===
          "auth/invalid-password" ||
        error?.code ===
          "auth/password-does-not-meet-requirements"
      ) {
        return res.status(
          400
        ).json({
          ok: false,
          message:
            "Firebase rechazó la contraseña temporal por la política de seguridad configurada.",
        });
      }

      return res.status(
        500
      ).json({
        ok: false,
        message:
          "No se pudo completar el restablecimiento de contraseña.",
      });
    }
  }
);

export default router;
