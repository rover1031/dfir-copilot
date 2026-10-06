# Correlación entre fuentes (entrega D2)

Cuando un análisis tiene **dos o más archivos ingeridos**, al terminar cada uno se calcula sola la correlación entre ellos (también con el
botón «Recalcular» de la página del análisis). Es local, por código y sin modelo, sobre los datos reales; se guarda en
`<análisis>/correlacion.json` con su SHA-256 en el ledger de cada caso implicado.

## Qué calcula

* **IPs compartidas** entre cualquier par de fuentes (web, firewall, endpoint...), con sus eventos en cada una.
* **Firewall × endpoint** (un caso de red y otro de endpoint con conexiones):
  1. Une cada conexión del endpoint con la del firewall de la misma IP de origen, IP de destino y puerto, la más cercana en el tiempo
     dentro de ±120 s.
  2. **Estima el desfase de relojes POR PAR origen-destino-puerto** (cada par vota una vez) y lo da por bueno solo si al menos la mitad
     de los pares coincide. Por conexión no sería fiable: con tráfico periódico (una baliza cada 600 s) y un desfase mayor que la ventana,
     cada conexión caería siempre a la misma distancia de la *siguiente* baliza y daría un desfase falso pero «consistente».
  3. Acepta como coincidencia la conexión que, corregido el desfase, cae dentro de ±2 s.
  4. Agrupa en **flujos** equipo · proceso → destino:puerto, con la acción que les dio el firewall.
  5. **Atribuye cada hallazgo del firewall** (que solo conoce la IP) al equipo y al proceso del endpoint, usando los destinos y puertos del
     hallazgo: «la baliza de 10.50.1.9 la abre `rundll32.exe` en WS-009». La IP → equipo sale del propio endpoint, con su ventana de tiempo.
  6. Marca si el endpoint señaló también ese equipo («señal en ambas fuentes»).

Con el simulador emparejado: desfase estimado 2,5 s exactos, todas las conexiones casan, y la baliza, la exfiltración y el barrido se
atribuyen a `rundll32.exe`, `rclone.exe` y `advanced_ip_scanner.exe` en sus equipos (`tests/test_correlation.py`).

## Privacidad

La página del análisis la muestra en alias (cada caso traduce lo que conoce) y con valores reales solo con el interruptor. El agente de
cada caso recibe un resumen sin valores reales: las IPs con el diccionario de ese caso, los equipos numerados (EQUIPO-1...) y los procesos
por su nombre de ejecutable.

## Límites

* Con **NAT** entre el equipo y el firewall, la IP de origen del firewall no es la del equipo: no habrá pares, y se dice.
* La seudonimización sigue siendo **por caso**: el mismo valor puede tener alias distintos en el firewall y en el endpoint. La correlación
  no lo necesita (trabaja sobre los datos reales, en local), pero el agente de un caso no puede consultar directamente el otro. Un
  diccionario compartido por análisis queda como siguiente paso.
