export function validarPasswordTemporal(
  password
) {
  if (
    typeof password !==
    "string"
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal no es válida.",
    };
  }

  if (
    password.length <
      10 ||
    password.length >
      128
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal debe tener entre 10 y 128 caracteres.",
    };
  }

  if (
    !/[A-Z]/.test(
      password
    )
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal debe contener al menos una letra mayúscula.",
    };
  }

  if (
    !/[a-z]/.test(
      password
    )
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal debe contener al menos una letra minúscula.",
    };
  }

  if (
    !/[0-9]/.test(
      password
    )
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal debe contener al menos un número.",
    };
  }

  if (
    !/[^A-Za-z0-9]/.test(
      password
    )
  ) {
    return {
      valido: false,
      mensaje:
        "La contraseña temporal debe contener al menos un carácter especial.",
    };
  }

  return {
    valido: true,
    mensaje: "",
  };
}
