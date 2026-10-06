# Logs de texto (`.log`, `.txt`)

Al añadir un archivo de texto a un análisis, se reconoce solo mirando sus primeras líneas y se convierte en uno o más CSV derivados,
que se analizan como cualquier otro log. El original queda como evidencia con su hash; cada derivado registra en la custodia de qué
archivo y de qué formato sale, cuántas filas tiene y **cuántas líneas se descartaron** (nunca en silencio).

| Formato | Qué sale |
|---|---|
| Syslog de **Palo Alto PAN-OS**, TRAFFIC y THREAT, con o sin cabecera syslog | un CSV por tipo (`__traffic.csv`, `__threat.csv`), cada uno un caso, analizado con el esquema de red |
| Logs de acceso **Nginx / Apache** (formatos combined y common) | un CSV de acceso analizado con el esquema web; la hora trae su desfase, así que la zona viene en el dato |

Posiciones de campo de PAN-OS según la documentación oficial (iguales en 9.1, 10.x y 11.x para los campos usados): Generated Time (6),
Source/Destination Address (7, 8), Rule (11), Source User (12), Application (14), zonas (16, 17), Session ID (22), puertos (24, 25),
Protocol (29), Action (30); en TRAFFIC, Bytes Sent/Received (32, 33) y Device Name (52, o el número de serie si no viene); en THREAT,
URL/Filename (31), Threat ID (32), Category (33) y Severity (34).

Límites: la URL y la categoría de THREAT se conservan en el CSV derivado, pero su análisis como proxy llega en la entrega C. Las horas de
PAN-OS no traen zona: queda «sin verificar» hasta que la confirmes. Otros formatos de texto se rechazan diciendo cuáles se reconocen.

El simulador escribe el mismo tráfico en syslog nativo (`synthetic_firewall.write_panos_syslog`); un test comprueba que da EXACTAMENTE los
mismos hallazgos que el CSV exportado de Palo Alto.
