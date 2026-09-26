// Servidor Sellia — firma tarjetas de Apple Wallet (.pkpass).
// Variables de entorno (acepta los dos nombres de cada una):
//   CLAVE_PANEL                         → clave que se pega en el panel de sellia.cloud
//   APPLE_TEAM_IDENTIFIER | TEAM_ID     → Team ID de Apple Developer (10 caracteres)
//   APPLE_P12_PASSWORD | CERT_PASSWORD  → contraseña del archivo .p12
//   PASS_TYPE_ID                        → opcional, si no es pass.com.incanto.fidelizacion
//   APPLE_P12_PATH                      → opcional, ruta del .p12 (por defecto se busca en /etc/secrets)
const fs = require('fs');
const path = require('path');
const express = require('express');
const forge = require('node-forge');
const { PKPass } = require('passkit-generator');

const PUERTO = process.env.PORT || 10000;
const CLAVE_P12 = process.env.APPLE_P12_PASSWORD || process.env.CERT_PASSWORD || '';
const TEAM_ID = (process.env.APPLE_TEAM_IDENTIFIER || process.env.TEAM_ID || '').trim();
const CLAVE_PANEL = process.env.CLAVE_PANEL || '';
const PASS_TYPE_ID = (process.env.PASS_TYPE_ID || '').trim();
const MODELO = path.join(__dirname, 'modelo.pass');

let certificados = null, errorArranque = null, rutaUsada = '';

// Busca el .p12: primero la ruta indicada, luego cualquier .p12 en /etc/secrets o junto al servidor.
function localizarP12() {
  const candidatos = [];
  if (process.env.APPLE_P12_PATH) candidatos.push(process.env.APPLE_P12_PATH);
  candidatos.push('/etc/secrets/PerfumeriaIncanto.p12');
  for (const dir of ['/etc/secrets', __dirname]) {
    try { for (const f of fs.readdirSync(dir)) if (/\.p12$/i.test(f)) candidatos.push(path.join(dir, f)); } catch (e) {}
  }
  return candidatos.find(r => { try { return fs.existsSync(r) && fs.statSync(r).isFile(); } catch (e) { return false; } });
}

// Corrige nombres de iconos (GitHub a veces cambia @ por -)
for (const [de, a] of [['icon-2x.png', 'icon@2x.png'], ['icon-3x.png', 'icon@3x.png'], ['logo-2x.png', 'logo@2x.png']]) {
  try {
    if (fs.existsSync(path.join(MODELO, de)) && !fs.existsSync(path.join(MODELO, a))) fs.copyFileSync(path.join(MODELO, de), path.join(MODELO, a));
  } catch (e) {}
}

function extraerP12(ruta, clave) {
  const buf = fs.readFileSync(ruta);
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(buf.toString('binary')), clave);
  } catch (e) {
    // El archivo fue pegado como texto base64 en Render — lo decodificamos
    let der;
    try {
      der = Buffer.from(buf.toString('utf8').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64').toString('binary');
      p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), clave);
    } catch (e2) {
      throw new Error('No se pudo abrir el .p12. Casi siempre es la contraseña (APPLE_P12_PASSWORD) incorrecta, o el archivo está dañado. Detalle: ' + e.message);
    }
  }
  let key = null, cert = null;
  for (const safe of p12.safeContents) for (const bag of safe.safeBags) {
    if ((bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) && bag.key) key = forge.pki.privateKeyToPem(bag.key);
    if (bag.type === forge.pki.oids.certBag && bag.cert && !cert) cert = forge.pki.certificateToPem(bag.cert);
  }
  if (!key || !cert) throw new Error('El .p12 no contiene certificado y llave privada juntos. Vuelve a exportarlo incluyendo la llave.');
  return { key, cert };
}

// WWDR G4: se descarga de Apple; si falla, se usa la copia local incluida en el repo.
async function obtenerWWDR() {
  const local = path.join(__dirname, 'wwdr-g4.pem');
  try {
    const r = await fetch('https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const der = Buffer.from(await r.arrayBuffer()).toString('binary');
    const pem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(der)));
    try { fs.writeFileSync(local, pem); } catch (e) {}
    return pem;
  } catch (e) {
    if (fs.existsSync(local)) return fs.readFileSync(local, 'utf8');
    throw new Error('No se pudo obtener el certificado WWDR de Apple: ' + e.message);
  }
}

async function preparar() {
  try {
    rutaUsada = localizarP12();
    if (!rutaUsada) throw new Error('No se encontró ningún archivo .p12. Súbelo en Render como Secret File (nombre sugerido: PerfumeriaIncanto.p12).');
    if (!CLAVE_P12) throw new Error('Falta la variable APPLE_P12_PASSWORD (contraseña del .p12).');
    if (!TEAM_ID) throw new Error('Falta la variable APPLE_TEAM_IDENTIFIER (Team ID de Apple).');
    if (!CLAVE_PANEL) throw new Error('Falta la variable CLAVE_PANEL.');
    const { key, cert } = extraerP12(rutaUsada, CLAVE_P12);
    const wwdr = await obtenerWWDR();
    certificados = { wwdr, signerCert: cert, signerKey: key };
    console.log('✅ Certificados listos (' + rutaUsada + '). Servidor Sellia en marcha.');
  } catch (e) {
    errorArranque = e.message;
    console.error('⚠️ ' + e.message);
  }
}

const app = express();

app.get('/', (req, res) => {
  res.type('html').send('<meta charset="utf-8"><body style="font-family:sans-serif;background:#080A12;color:#fff;padding:40px"><h2>Servidor Sellia</h2><p>' +
    (certificados ? '✅ Todo listo: los certificados están cargados y se pueden firmar tarjetas.' : '⚠️ Falta configuración: ' + (errorArranque || 'iniciando…')) +
    '</p><p style="color:#AAB2C8">Team ID: ' + (TEAM_ID || '(vacío)') + ' · Pass Type: ' + (PASS_TYPE_ID || leerPassType()) + '</p></body>');
});

app.get('/salud', (req, res) => res.json({ listo: !!certificados, error: errorArranque, teamId: TEAM_ID, passType: PASS_TYPE_ID || leerPassType() }));

function leerPassType() {
  try { return JSON.parse(fs.readFileSync(path.join(MODELO, 'pass.json'), 'utf8')).passTypeIdentifier || ''; } catch (e) { return ''; }
}

app.get('/api/pase', async (req, res) => {
  try {
    if (!certificados) return res.status(503).type('text').send('El servidor no está listo: ' + (errorArranque || 'iniciando'));
    const q = req.query;
    if (!CLAVE_PANEL || q.k !== CLAVE_PANEL) return res.status(401).type('text').send('Clave del panel incorrecta.');
    const nombre = String(q.nombre || '').slice(0, 60);
    const negocio = String(q.negocio || 'Sellia').slice(0, 40);
    const codigo = String(q.codigo || '').slice(0, 20);
    const puntos = String(parseInt(q.puntos, 10) || 0);
    const nivel = String(q.nivel || 'Bronce').slice(0, 12);
    const enlace = String(q.enlace || 'https://sellia.cloud').slice(0, 300);
    if (!nombre || !codigo) return res.status(400).type('text').send('Faltan datos del cliente (nombre y código).');
    const lat = parseFloat(q.lat), lng = parseFloat(q.lng);
    const hayUbicacion = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
    const alerta = String(q.alerta || ('Estás cerca de ' + negocio + '. ¡Muestra tu tarjeta y suma un sello!')).slice(0, 120);

    const props = {
      serialNumber: codigo + '-' + Date.now(),
      teamIdentifier: TEAM_ID,
      organizationName: negocio,
      logoText: negocio,
      description: 'Tarjeta de sellos de ' + negocio,
      maxDistance: 100
    };
    if (PASS_TYPE_ID) props.passTypeIdentifier = PASS_TYPE_ID;

    const pase = await PKPass.from({ model: MODELO, certificates: certificados }, props);
    if (hayUbicacion) pase.setLocations({ latitude: lat, longitude: lng, relevantText: alerta });
    pase.setBarcodes({ message: enlace, format: 'PKBarcodeFormatQR', messageEncoding: 'iso-8859-1', altText: codigo });
    pase.primaryFields.push({ key: 'puntos', label: 'SELLOS', value: puntos });
    pase.secondaryFields.push({ key: 'nombre', label: 'CLIENTE', value: nombre });
    pase.secondaryFields.push({ key: 'nivel', label: 'NIVEL', value: nivel });
    pase.auxiliaryFields.push({ key: 'codigo', label: 'CÓDIGO DE AFILIADO', value: codigo });
    pase.backFields.push({ key: 'info', label: negocio, value: 'Tarjeta de sellos. Acumula sellos en cada compra y reclama tu premio.' + (hayUbicacion ? ' Recibirás un aviso cuando estés cerca del local.' : '') });

    const buffer = pase.getAsBuffer();
    res.set({ 'Content-Type': 'application/vnd.apple.pkpass', 'Content-Disposition': 'attachment; filename="sellia-' + codigo + '.pkpass"' });
    res.send(buffer);
  } catch (e) {
    console.error(e);
    res.status(500).type('text').send('No se pudo generar la tarjeta: ' + e.message);
  }
});

app.listen(PUERTO, () => { console.log('Escuchando en el puerto ' + PUERTO); preparar(); });
