# firma-it

Firma electrónica **CAdES / PAdES / XAdES** en un único binario de **8 MB**, sin
Electron (240 MB) ni JVM (90 MB), sin código propietario. Para el uso diario,
produce artefactos que cualquier validador europeo acepta.

```bash
firma-it sign contratto.pdf --p12 mario.p12 --pass secret \
    --reason "Contratto di fornitura" --box 100,600,300,700
# → contratto_signed.pdf, PAdES-B, ETSI EN 319 142-1
```

---

## Por qué

Hay programas de firma de cientos de MB, con Electron y una JVM, para producir
un fichero que es **100 % ETSI**. Lo que la normativa exige no es el programa, es el perfil de
firma: los tamaños y el método de análisis están en
[`doc/DECISIONES.md`](doc/DECISIONES.md).

| Formato | Norma | Fichero | Nivel |
|---|---|---|---|
| CAdES | ETSI EN 319 122-1 | `.p7m` contenido embebido | BES / T |
| PAdES | ETSI EN 319 142-1 | `_signed.pdf` | B / T |
| XAdES | ETSI EN 319 132-1 | `_signed.xml` | BES |

---

## Estado real, medido

| Capacidad | Estado | Verificación externa |
|---|---|---|
| PAdES-B con sello visible | ✅ | `pdfsig`: `Signature is Valid` |
| CAdES-BES `.p7m` | ✅ | `openssl cms -verify`: `CAdES Verification successful` |
| CAdES-T con sello RFC 3161 | ✅ | `openssl` + pyHanko: sello `intact` y `trusted` |
| Sello en hueco exacto | ✅ | datos del certificado, 64×48 pt, sin truncar |
| Varios sellos, una firma | ✅ | `--box` repetible; `seal_count` en el JSON |
| Varias firmas encadenadas | ✅ | 5 firmas válidas en un PDF |
| P12 de cualquier CA o autofirmado | ✅ | se firma y se reporta el estado |
| XAdES-BES (enveloped y enveloping) | ✅ | `signxml` (implementación independiente): firma y digests válidos |
| PKCS#11 smartcard | ⚠️ | compila; sin tarjeta en esta máquina para probar |
| App nativa Fyne (es/it/en) | ✅ | 39 hilos, ventana 868×712, cero fallos de traducción |
| PAdES B-LT / B-LTA | ❌ | la librería devuelve `format 3 is not currently supported` |
| XAdES-T | ❌ | falta `xades:SignatureTimeStamp` |

**Lo que no está probado no se anuncia como hecho.** Ver
[`doc/DECISIONES.md`](doc/DECISIONES.md).

---

## Instalación

```bash
# CLI estático, sin dependencias (P12 y PEM) — 8 MB
make build

# app nativa de escritorio (Fyne) — 32 MB, requiere cgo
make deps-gui    # lista los paquetes del sistema
make build-gui

# CLI con smartcard (requiere cgo y libdl)
make build-token
```

### App nativa: coste real

Fyne exige CGO y cabeceras del sistema, así que **el binario de escritorio no es
estático y no se cross-compila sin toolchain por plataforma**. El CLI sí (8 MB,
5 plataformas). Si `make build-gui` falla con `fatal error: wayland-client-core.h`,
faltan los paquetes de `make deps-gui`. Es el precio de una ventana nativa.

### Dependencias de la app nativa

```bash
# Debian/Ubuntu
sudo apt install gcc pkg-config libgl1-mesa-dev xorg-dev \
    libxkbcommon-dev libwayland-dev libegl1-mesa-dev

# Fedora
sudo dnf install gcc pkg-config mesa-libGL-devel libX11-devel \
    libXcursor-devel libXrandr-devel libXinerama-devel libXi-devel \
    wayland-devel libxkbcommon-devel

# macOS
xcode-select --install

# Windows: MSYS2 con mingw-w64
```

La GUI es un **frontal del mismo binario**: no reimplementa nada, ejecuta
`firma-it` y muestra el resultado. Por eso CLI y app no pueden divergir.

Cross-compile:

```bash
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o bin/firma-it-macos  ./src/entrypoint/main
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/firma-it.exe    ./src/entrypoint/main
```

---

## Uso

### Firmar con P12 (cualquier autoridad, o autofirmado)

```bash
firma-it sign contratto.pdf --p12 mario.p12 --pass secret
firma-it sign fattura.xml  --format cades --p12 mario.p12
firma-it sign atto.xml     --format xades --p12 mario.p12 --enveloping
```

### El sello

El sello se rellena **solo con datos del certificado**: nombre (givenName +
surname), identificador nacional (`serialNumber`, o `organizationIdentifier`),
fecha, hora y zona. No hay campo de texto: nada de lo que imprimes lo escribes tú.

```
MARIA
LOPEZ GARCIA
IDCES-00000000X
2026-11-02
20:37:01 +01:00
```

Tamaño por defecto: **64×48 pt** (~23×17 mm). No es un tamaño ETSI (no existe
tal cosa); es una elección de presentación para que quepa en el margen sin tapar
texto. Si la identidad no cabe, la firma **falla** en vez de truncar.

### Varios sellos en un mismo paso

`--box` es repetible. Formas aceptadas:

```bash
# un sello por página, en un solo valor criptográfico
firma-it sign atto.pdf --p12 mario.p12 \
    --box 20,700,84,748 \
    --box 20,40,84,88

# página explícita por sello
firma-it sign atto.pdf --p12 mario.p12 \
    --box 1:20,700,84,748 \
    --box 12:20,40,84,88
```

Un documento puede llevar **varias marcas con una sola firma**: es lo correcto
para rúbricas. Si lo que quieres son **firmas distintas** (varios firmantes, o
una firma por página que cada una cubre la anterior), firma el PDF ya firmado:
cada pasada añade una firma incremental válida.

```bash
firma-it sign atto.pdf --p12 mario.p12 --out paso1.pdf
firma-it sign paso1.pdf --p12 mario.p12 --out paso2.pdf   # 2 firmas válidas
```

Coordenadas en puntos PDF (1 pt = 1/72"), origen abajo-izquierda. Sin `--box`:
sello por defecto en la esquina inferior derecha de `--page`.

### Con sello de tiempo

```bash
firma-it sign contratto.pdf --p12 mario.p12 --level t --tsa https://tsa.example/
firma-it sign fattura.xml  --format cades --p12 mario.p12 --level t --tsa https://tsa.example/
```

La TSA de Aruba (`servizi.arubapec.it/tsa/ngrequest.php`) devuelve `401` sin
cuenta. Cualquier QTST de la lista eIDAS sirve.

### Con smartcard

```bash
firma-it sign atto.pdf --token "Carta de Ejemplo" --pin 000000
firma-it sign atto.pdf --token "Carta de Ejemplo" --pin 000000 --format cades
```

Requiere `pcscd` activo y `opensc-pkcs11.so`. `--module` para otra ruta.

### Salida para agentes de IA

```bash
firma-it sign doc.pdf --p12 k.p12 --pass s --json
```

```json
{
  "path": "doc_signed.pdf",
  "format": "pades",
  "standard": "ETSI EN 319 142-1",
  "level": "bes",
  "size_bytes": 9698,
  "signed_at": "2026-11-02T18:17:58+01:00",
  "signer": "signer",
  "has_seal": true
}
```

Códigos de salida: `0` firmado, `1` fallo de firma, `2` error de uso.

---

## Compatibilidad con AutoFirma / "Refirma"

Mismo contrato observable, sin copiar código (AutoFirma es GPL-2.0 + EUPL-1.1):

| Aspecto | AutoFirma | firma-it |
|---|---|---|
| P12/PFX | ✅ | ✅ |
| PKCS#11 | ✅ | ✅ (build con CGO) |
| CAdES `.p7m` | ✅ | ✅ |
| PAdES | ✅ | ✅ (B y B-T) |
| XAdES | ✅ | ✅ (BES) |
| Autofirmados | acepta | acepta y reporta |
| Convención de nombres | `_signed` / `.p7m` | idéntica |

Un documento firmado por cualquiera de los dos valida en el otro.

---

## Limitaciones honestas

- **B-LT/B-LTA no nativo**: `digitorus/pdfsign` v1.0.0 aún no escribe el `/DSS`.
  `--level lt` falla con un mensaje que explica las alternativas en vez de
  producir un fichero con el perfil equivocado.
- **XAdES** se compone con `encoding/xml` + `etree`, usando solo el
  canonicalizador de `goxmldsig` (la única librería XAdES completa en Go,
  `goxades`, tiene ★10 y ningún commit desde 2023: no es aceptable para firmar).
  Verificado con `signxml`; **XAdES-T** (sello de tiempo sobre el XML) sigue
  pendiente.
- **PKCS#11** rompe el binario estático: `miekg/pkcs11` usa cgo y `-ldl`.
  Por eso hay dos builds.
- **Idioma**: los mensajes están en inglés. La localización es/en/it está
  planificada, no hecha.

---

## Estructura

Vertical slices con DDD y Clean Architecture; sin `domain/` global.

```
src/
  signing/                     firmar documentos
    domain/                    Format, Level, Document, SealPlacement, Signer
    application/               SignDocument + puertos (CadesSigner, FileStore…)
    infrastructure/            p12 · pem · pkcs11 · cms (DER propio) · pdfsign · xades
  entrypoint/
    cli/                       adaptador de consola
    main/                      main()
tests/
  signing/domain/              reglas de negocio
  signing/application/         caso de uso con dobles de prueba
  signing/integration/         CMS contra OpenSSL
```

El núcleo (`domain`) no importa nada de terceros. `cms/` no usa ninguna
librería de CMS: escribe DER a mano porque CAdES-T necesita añadir un atributo
*firmado después* de que exista el valor de firma.

---

## Verificar a mano lo que produce

```bash
# CAdES
openssl cms -verify -in doc.p7m -inform DER -CAfile ca.pem -purpose any -cades
openssl asn1parse -inform DER -in doc.p7m | grep -E "signingCertificateV2|signingTime"

# PAdES
pdfsig doc_signed.pdf

# Extraer el contenido de un .p7m
openssl cms -verify -in doc.p7m -inform DER -CAfile ca.pem -purpose any -cades -out original
```

---

## Desarrollo

```bash
make build      # binario estático
make build-token
make test       # 30 tests (dominio, caso de uso, CMS contra OpenSSL)
make check      # tests + vet + gofmt
make cross      # las 5 plataformas
```

Versión: `0.2.0-unstable` (major 0, sin releases estables todavía). Licencia: GPL-3.0-or-later.

---

## Licencia

**GPL-3.0-or-later.** Es la recomendación de la FSF para programas, y aquí no es
solo ideología: una herramienta de firma cuyo código no puedes auditar es una
que tienes que creer. Cualquiera que distribuya una versión modificada debe
publicar el código, lo que mantiene inspeccionable el camino de la firma.

Todas las dependencias son permisivas (MIT, BSD, Apache-2.0, ISC), lo que hace
posible distribuir bajo GPL. El detalle está en [`LICENSE`](LICENSE).

No se ha copiado código propietario de AutoFirma ni de otros programas: los formatos
son estándares ETSI y la compatibilidad de `doc/` se midió contra esas
implementaciones, no se extrajo de ellas.
