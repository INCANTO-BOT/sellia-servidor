# Servidor Sellia · tarjetas de Apple Wallet

Genera y firma las tarjetas `.pkpass` que sellia.cloud entrega a los clientes.

## Despliegue en Render (Web Service)
- Runtime: Node · Build: `npm install` · Start: `node server.js`
- Variables de entorno:
  - `CLAVE_PANEL` — contraseña que luego se pega en el panel administrativo de sellia.cloud
  - `APPLE_TEAM_IDENTIFIER` — Team ID de Apple Developer (10 caracteres). También acepta `TEAM_ID`
  - `APPLE_P12_PASSWORD` — contraseña del archivo .p12. También acepta `CERT_PASSWORD`
  - `PASS_TYPE_ID` — opcional; solo si el Pass Type ID del certificado NO es `pass.com.incanto.fidelizacion`
- Secret File: el certificado `.p12` (nombre sugerido `PerfumeriaIncanto.p12`; se detecta cualquier `.p12` en /etc/secrets)

## Comprobación
Abre `https://TU-SERVICIO.onrender.com/` → debe decir "✅ Todo listo". `/salud` devuelve el estado en JSON.
