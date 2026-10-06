# Documentos PDF (boletines de amenazas)

Subir un PDF a un análisis lo lee y extrae sus indicadores **sin modelo**. La pantalla del documento («ver análisis →» en la lista de
archivos) muestra lo encontrado y permite preguntarle en lenguaje natural si se autoriza.

## Qué se extrae y cómo se valida

- **Indicadores:** hashes (MD5, SHA-1, SHA-256), IPv4, URL, dominio, `.onion`, correo y CVE. Se deshace la ofuscación habitual
  (`hxxp`, `[.]`, `(at)`).
- **Validación por forma:** un hash solo se acepta con 32, 40 o 64 caracteres hexadecimales; un `.onion` con 16 o 56; un dominio suelto
  con un TLD conocido (el host de una URL siempre cuenta). Lo que se parece pero no cuadra va a **dudosos** y nunca a la lista de bloqueo.
- **Cabecera y pie:** las líneas repetidas en casi todas las páginas (el sitio que publica, `1/6`) se quitan antes de extraer.
- **Servicios conocidos** (x.com, torproject.org, …) se etiquetan y quedan fuera de la lista de bloqueo, sin esconderse.
- **IPs privadas o reservadas** se marcan `no_publica` y quedan fuera de la lista de bloqueo.

## PDF escaneados (sin texto)

Un PDF impreso con «Microsoft Print to PDF» no tiene texto: se lee con **OCR** (Tesseract, inglés y español). Las tablas de hashes se
leen fila a fila por la geometría de sus líneas, a tres resoluciones. Aun así, **un hash leído por OCR nunca entra solo a la lista de
bloqueo**: queda como *candidato sin verificar* hasta contrastarlo con una fuente de texto (la página web del boletín, por ejemplo). La
verificación no repite el OCR: una coincidencia exacta lo verifica; una diferencia de hasta 3 caracteres con un único hash de la fuente lo
corrige y queda registrado.

Medido con un boletín real impreso desde el navegador: la longitud sola no detecta un carácter mal leído (el OCR leía `0` como `e` y
generaba hashes de longitud correcta pero falsos). Sin fuente, ningún hash de OCR llega a la lista de bloqueo; con la fuente, los 18 hashes
válidos presentes en el PDF quedaron exactos. El mismo boletín traía los SHA-256 truncados en origen (58-60 caracteres): se marcan como
dudosos, que es lo correcto.

**Consejo:** imprime los boletines web con «Guardar como PDF» del navegador, que conserva el texto; así no hace falta OCR.

## Resultados (en `data/projects/<análisis>/documents/<caso>/`)

`iocs.csv` (lista de bloqueo), `candidatos_ocr.csv`, `dudosos.csv`, `resumen.json` (estadísticas, países, resumen extractivo, avisos) y
`manifest.json` (SHA-256 del PDF, método de lectura de cada página). Se descargan desde la pantalla del documento; el texto de las páginas
no se ofrece para descarga.

## Preguntar al documento

Un agente pequeño, aparte del de investigación de logs, consulta el documento con herramientas acotadas (`buscar_en_documento`,
`ver_pagina`, `listar_iocs`, `estadisticas`, `pais_de_ip`). Garantías comprobadas por código:

- **Opt-in por documento:** por defecto no sale nada hacia el modelo; hay que permitirlo en cada documento.
- **Solo salen los pasajes necesarios**, y cada respuesta muestra qué herramienta, qué páginas y cuántos caracteres salieron.
- **Citas verificadas:** cada cita `«texto» (p.N)` se comprueba contra esa página; la que no existe se marca ⚠.
- **El texto del PDF no es confiable:** va aislado entre etiquetas y se neutraliza cualquier intento de cerrarlas o de dar órdenes.
- La búsqueda es léxica: el agente consulta en el idioma del documento y responde en el del analista.
