# Clang Process Isolation Sprint Plan

## Ziel

`exodus analyze` soll Clang-basierten Analysecode robust und parallel ausfuehren koennen, ohne In-Process-`libclang`-Instabilitaet.

Die Zielarchitektur ist:
- **ein separater Prozess pro Clang-Job**
- **keine gemeinsam genutzte `libclang`-Instanz im Python-Hauptprozess**
- **zentrale Zusammenfuehrung der Worker-Ergebnisse**
- **anschliessender Cross-TU-Pass im Hauptprozess**

## Aktueller Stand

Es gibt bereits einen wichtigen Teil der Architektur:
- Clang-Analyse wird ueber `clang_worker.py` in Subprozessen ausgefuehrt
- der Hauptprozess sammelt JSON-Ergebnisse wieder ein

Relevante Stellen:
- [analyze.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L1353)
- [clang_worker.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/clang_worker.py#L1)
- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py#L147)

## Ist-Stand als ASCII

```text
                    exodus analyze
                          |
                          v
                +-------------------+
                |  Hauptprozess     |
                |  analyze.py       |
                +-------------------+
                  |            |
                  |            +-------------------------------+
                  |                                            |
                  v                                            v
      +-------------------------+                  +--------------------------+
      | Tree-sitter Pass        |                  | Clang TU Pass            |
      | parallel im Prozess     |                  | pro Datei subprocess     |
      +-------------------------+                  +--------------------------+
                  |                                            |
                  |                                            |
                  |                               subprocess.run(... clang_worker)
                  |                                            |
                  |                                            v
                  |                              +-----------------------------+
                  |                              | Worker-Prozess              |
                  |                              | clang_worker.py             |
                  |                              | import clang.cindex         |
                  |                              | load libclang               |
                  |                              | parse 1 TU                  |
                  |                              | analyze AST                 |
                  |                              | emit JSON                   |
                  |                              +-----------------------------+
                  |                                            |
                  +----------------------------+---------------+
                                               |
                                               v
                                   +--------------------------+
                                   | Hauptprozess sammelt     |
                                   | Violations + Cross-TU DB |
                                   +--------------------------+
                                               |
                                               v
                              +--------------------------------------+
                              | Post-Pass / General Rules            |
                              | _record_cpp_general_rules            |
                              +--------------------------------------+
                                               |
                                               v
                         +-----------------------------------------------+
                         | Header-Scan fuer Rule 3-1-1 etc.              |
                         | derzeit wieder DIREKT im Hauptprozess mit     |
                         | clang.cindex.Index.create()                   |
                         +-----------------------------------------------+
```

### Wichtiger Architekturbruch

```text
TU-Analyse:
  isoliert, prozessbasiert, robuster

Header-/General-Rules-Pass:
  noch in-process libclang
  => architektonisch inkonsistent
```

### Datenfluss

```text
[Source Files]
     |
     +--> Tree-sitter --> Violations
     |
     +--> Clang Worker Prozesse --> JSON --> Hauptprozess
                                            |
                                            +--> global_db / Cross-TU
                                            |
                                            +--> General Rules
                                                  |
                                                  +--> Header scan mit libclang
```

### Aktuelle Problemzone

```text
55/55 TUs fertig
      |
      v
_record_cpp_general_rules(...)
      |
      v
_scan_header_rule_3_1_1_with_clang(...)
      |
      v
clang.cindex im Hauptprozess
      |
      +--> langsam / haengt / nicht sauber isoliert
```

Trotzdem gibt es noch Baustellen:
- Worker-Timeouts auf schweren TUs
- zu schwache Diagnose bei haengenden Files
- noch kein explizites Architektur-Commitment, dass **nur** Prozessisolation der stabile Pfad ist
- Cross-TU-Zusammenfuehrung ist funktional da, aber noch nicht als eigenes Subsystem klar geschnitten

## Architekturentscheidung

Die empfohlene Linie ist:

1. **Keine Rueckkehr zu shared `libclang` im Hauptprozess**
2. **Keine Python-Thread-Parallelisierung mit gemeinsamer `clang.cindex`-Instanz**
3. **Alle Clang-AST-Arbeit nur in isolierten Worker-Prozessen**
4. **Cross-TU nur auf JSON-/Datenbank-Ebene im Hauptprozess**

Das entspricht dem stabilen Modell:
- Compiler-Binaries parallel ueber Prozesse
- nicht eine globale Library in vielen Threads

## Betroffene Python-Dateien

### Primär

- [analyze.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py)
  - Worker-Start
  - Timeout
  - Retry-Strategie
  - Ergebniszusammenfuehrung
  - Cross-TU-Nachlauf

- [clang_worker.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/clang_worker.py)
  - Prozess-Einstieg
  - `clang.cindex`-Import
  - `Config.set_library_file`
  - TU-Parse
  - JSON-Output

- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py)
  - Analyze-Config-Felder
  - z. B. Timeout / Worker-Parallelitaet / Parse-Only-Fallback

### Sekundär

- [cli.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/core/cli.py)
  - falls neue CLI-Schalter fuer Debug/Isolation/Timeout gewuenscht sind

- [libclang_config.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/libclang_config.py)
  - stabile und explizite Aufloesung der richtigen `libclang`

- Templates unter
  - [templates/misra-c2012/exodus.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/templates/misra-c2012/exodus.json)
  - [templates/misra-c2023/exodus.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/templates/misra-c2023/exodus.json)
  - [templates/misra-cpp2008/exodus.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/templates/misra-cpp2008/exodus.json)
  - [templates/misra-cpp2023/exodus.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/templates/misra-cpp2023/exodus.json)

## Sprintplanung

### sprint_task_1_process_model_hardening

Ziel:
- die Prozess-Isolation als einzige Clang-Architektur festziehen

Arbeit:
- in [analyze.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py) dokumentieren, dass Clang nur ueber Worker-Prozesse laufen soll
- bestehende In-Process-Clang-Pfade pruefen und markieren
- sicherstellen, dass neue Features nicht versehentlich wieder shared `clang.cindex` im Hauptprozess benutzen

Konkrete Stellen:
- [analyze.py#L631](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L631)
- [analyze.py#L1353](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L1353)

Definition of Done:
- der Codepfad fuer produktive Clang-Analyse ist eindeutig prozessbasiert
- Architekturkommentar im Code ist klar

### sprint_task_2_worker_config_surface

Ziel:
- Worker-Verhalten sauber konfigurierbar machen

Arbeit:
- bestehendes Feld `clang_worker_timeout_sec` nutzen und dokumentieren
- optional weitere Felder einfuehren:
  - `clang_worker_parallelism`
  - `clang_parse_only_on_timeout`
  - `clang_parse_only_on_crash`

Konkrete Stellen:
- [project.py#L147](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py#L147)
- [analyze.py#L1359](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L1359)
- [cli.py#L107](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/core/cli.py#L107)

Definition of Done:
- Worker-Timeout und Fallbacks sind projektseitig steuerbar
- keine Magic Number `30` mehr im Clang-Prozesspfad

### sprint_task_3_worker_observability

Ziel:
- haengende oder langsame TUs sauber diagnostizierbar machen

Arbeit:
- `clang_debug.jsonl` weiter ausbauen
- Trace-Dateien pro Worker standardisieren
- bei Timeout mehr Kontext loggen:
  - Quelle
  - Libclang-Pfad
  - relevante Args
  - Parse-Only-Retry ja/nein

Konkrete Stellen:
- [analyze.py#L1364](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L1364)
- [analyze.py#L1390](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L1390)
- [clang_worker.py#L106](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/clang_worker.py#L106)

Definition of Done:
- fuer Timeout-Faelle ist die Diagnose ausreichend, ohne den Lauf erneut instrumentieren zu muessen

### sprint_task_4_cross_tu_contract_cleanup

Ziel:
- Cross-TU klar von TU-Analyse entkoppeln

Arbeit:
- festlegen, welche Daten Worker liefern muessen
- JSON-Vertrag dokumentieren:
  - Violations
  - Identifier
  - ext_objects
  - Signaturen
- Cross-TU-Pass im Hauptprozess explizit als zweite Phase markieren

Konkrete Stellen:
- [clang_worker.py#L17](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/clang_worker.py#L17)
- [clang_worker.py#L126](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/clang_worker.py#L126)
- [analyze.py#L2047](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L2047)

Definition of Done:
- Worker und Hauptprozess haben einen klaren, stabilen Datenvertrag
- Cross-TU-Regeln bleiben moeglich, obwohl jede TU isoliert analysiert wird

### sprint_task_5_worker_pool_policy

Ziel:
- Parallelitaet kontrolliert und reproduzierbar machen

Arbeit:
- festlegen, wie viele Worker gleichzeitig laufen duerfen
- harte CPU-/RAM-Spitzen vermeiden
- optional projektseitig limitierbar machen

Konkrete Stellen:
- Clang-Future-Erzeugung in [analyze.py#L2029](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py#L2029)
- ThreadPool-/Executor-Policy in [analyze.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py)

Definition of Done:
- Workerzahl ist nicht mehr implizit
- große Projekte laufen stabiler und vorhersagbarer

### sprint_task_6_spec_and_docs

Ziel:
- die Analysearchitektur dokumentieren

Arbeit:
- README/Docs ergaenzen:
  - warum Prozess-Isolation
  - warum nicht shared `clang.cindex`
  - wie `clang_library_file` und `clang_worker_timeout_sec` gesetzt werden
- Templates angleichen

Konkrete Stellen:
- [README.md](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/README.md)
- [libclang_explanation.md](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/libclang_explanation.md)
- MISRA-Templates unter `exodus/templates/`

Definition of Done:
- Nutzer koennen die Clang-Analyse konfigurieren, ohne Quellcode lesen zu muessen

## Teststrategie

### Python-Level Tests

Abzusichern:
- Timeout-Feld wird aus Config gelesen
- Worker bekommt Timeout korrekt
- Timeout fuehrt zu parse-only-Retry
- Retry-Erfolg wird sauber behandelt
- Retry-Fehlschlag fuehrt zu sauberem Skip

Betroffene Stellen:
- Tests fuer [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py)
- Tests fuer [analyze.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/analyze/analyze.py)

### E2E-Tests

Sinnvolle E2E-Faelle:
- kleines Projekt: Clang komplett erfolgreich
- schweres Projekt: mindestens keine instabile In-Process-Nutzung
- Timeout-Fall: parse-only-Retry sichtbar
- Cross-TU-Daten werden trotz Worker-Isolation korrekt zusammengefuehrt

## Empfohlene Reihenfolge

1. `sprint_task_1_process_model_hardening`
2. `sprint_task_2_worker_config_surface`
3. `sprint_task_3_worker_observability`
4. `sprint_task_4_cross_tu_contract_cleanup`
5. `sprint_task_5_worker_pool_policy`
6. `sprint_task_6_spec_and_docs`

## Pragmatisches Urteil

Die richtige Richtung ist **nicht**, das PyPI-Binding thread-sicher patchen zu wollen.

Die richtige Richtung ist:
- `clang.cindex` nur in Worker-Prozessen
- stabile JSON-Ergebnisse an den Hauptprozess
- globaler Cross-TU-Pass danach

Damit bekommt ihr:
- Stabilitaet wie bei separaten Compiler-Prozessen
- und trotzdem weiter Cross-TU-Heuristiken.
