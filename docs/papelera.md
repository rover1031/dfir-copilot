# Papelera: eliminar análisis

En DFIR un análisis lleva evidencia y su cadena de custodia, así que eliminar tiene dos pasos.

1. **Mover a la papelera** («Eliminar…» en la tarjeta del análisis o en un caso suelto): hay que escribir su identificador. Desaparece de
   la lista pero se puede **restaurar tal cual**: la custodia sigue íntegra y sus informes exportados vuelven con él. No se puede eliminar
   mientras algo se está analizando.
2. **Eliminar definitivamente** desde la papelera (escribiendo de nuevo el identificador) o **vaciarla** (escribiendo `VACIAR`).

Cada paso queda en un **registro de eliminaciones** (`data/papelera/registro.jsonl`) encadenado por hashes como la custodia: quién,
cuándo, qué archivos con su SHA-256 y el último hash de la custodia del análisis. Si alguien lo edita a mano, la papelera lo detecta y lo
muestra. Queda constancia de que hubo evidencia y de que se eliminó, aunque ya no exista.

- Un análisis **vinculado a una carpeta del servidor** se elimina sin tocar esa carpeta: solo se mueven los datos del análisis.
- Restaurar **nunca sobrescribe**: si ya existe otro análisis con ese identificador, se rechaza.
- Mover es un renombrado dentro de la raíz de datos: no se copia evidencia ni se duplica espacio. El espacio se libera al eliminar
  definitivamente.
