import "dotenv/config";

import express from "express";
import cors from "cors";

import {
  rateLimit,
} from "express-rate-limit";

import usuariosRoutes from "./routes/usuariosRoutes.js";

const app =
  express();

const PORT =
  Number(
    process.env.PORT ||
    3001
  );

const ORIGENES =
  String(
    process.env
      .ALLOWED_ORIGINS ||
      "http://localhost:5173,http://127.0.0.1:5173"
  )
    .split(",")
    .map(
      (origen) =>
        origen.trim()
    )
    .filter(
      Boolean
    );

app.disable(
  "x-powered-by"
);

app.set(
  "trust proxy",
  1
);

app.use(
  express.json({
    limit:
      "20kb",
  })
);

app.use(
  cors({
    origin(
      origin,
      callback
    ) {
      /*
       * Solicitudes sin Origin:
       * curl, health checks y herramientas del servidor.
       */
      if (!origin) {
        return callback(
          null,
          true
        );
      }

      if (
        ORIGENES.includes(
          origin
        )
      ) {
        return callback(
          null,
          true
        );
      }

      return callback(
        new Error(
          "Origen no permitido."
        )
      );
    },

    methods: [
      "GET",
      "POST",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],

    maxAge:
      86400,
  })
);

const limitadorPassword =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit:
      10,

    standardHeaders:
      "draft-8",

    legacyHeaders:
      false,

    message: {
      ok: false,

      message:
        "Se realizaron demasiados intentos de restablecimiento. Espere unos minutos.",
    },
  });

app.get(
  "/salud",
  (
    req,
    res
  ) => {
    res.status(
      200
    ).json({
      ok: true,
      servicio:
        "RiberGas Password Admin API",
    });
  }
);

app.use(
  "/usuarios",
  limitadorPassword,
  usuariosRoutes
);

app.use(
  (
    req,
    res
  ) => {
    res.status(
      404
    ).json({
      ok: false,
      message:
        "Ruta no encontrada.",
    });
  }
);

/*
 * Express 5:
 * el middleware de error conserva una respuesta JSON
 * incluso para errores de CORS.
 */
app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Error HTTP:",
      error
    );

    if (
      error?.message ===
      "Origen no permitido."
    ) {
      return res.status(
        403
      ).json({
        ok: false,
        message:
          "El origen de la aplicación no está autorizado.",
      });
    }

    return res.status(
      500
    ).json({
      ok: false,
      message:
        "Error interno del servicio.",
    });
  }
);

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `RiberGas Password Admin API escuchando en puerto ${PORT}.`
    );
  }
);
