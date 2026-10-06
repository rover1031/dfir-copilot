# Vista del incidente (entrega E1)

Un **análisis** es el incidente; cada archivo es una **fuente de evidencia** con su propio esquema, ledger, copia seudonimizada y detectores.
La página del análisis ahora los reúne SIN mezclar su procedencia:

* **Fuentes de evidencia**: la tabla de archivos de siempre (avance, consumo, «Abrir caso» para el detalle técnico de cada fuente).
* **🧭 Incidente → Hallazgos**: los hallazgos de todas las fuentes juntos, ordenados por severidad, cada uno con la etiqueta de su fuente
  (color fijo por tipo: firewall azul, endpoint ámbar, web verde, correlación lila; el nombre del archivo y su SHA-256 al pasar el ratón)
  y enlace a esa fuente.
* **🧭 Incidente → Línea de tiempo**: en UTC, en orden: entrada de cada archivo en la custodia; inicio y último evento de lo que señala
  cada hallazgo (con su destino, si lo tiene: el inicio de la baliza, no el de toda la actividad de la IP); primeras conexiones atribuidas
  por la correlación; hipótesis, decisiones y notas. Las horas del dato de una fuente de endpoint correlacionada van **corregidas con el
  desfase de relojes estimado** y marcadas con ⏱; las de la custodia son de esta máquina y no se corrigen.
* **🔗 Correlación entre fuentes** (entrega D2).
* **🪙 Tokens del incidente**: la suma de todas las fuentes y su reparto. El asistente admite un **tope del incidente** (opcional): al
  alcanzarlo, la interpretación y el triaje se saltan y «Preguntar» se bloquea; lo local (perfil, detectores, preguntas rápidas,
  correlación) sigue funcionando.

Todo se muestra en alias (cada fuente con su diccionario) y con valores reales solo con el interruptor.

Siguiente (E2): diccionario de alias compartido por análisis (solo análisis nuevos), un agente del incidente que consulta todas las fuentes
y da su valoración (¿incidente?, ¿qué ataque?, confianza, evidencia a favor y en contra), e informes por fuente y del incidente al pulsar.
