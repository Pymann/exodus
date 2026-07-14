# Exodus Dependency Resolution Report

## Kurzfazit

`exodus` hat aktuell eine brauchbare inkrementelle Rebuild-Logik fuer Quell- und Header-Abhaengigkeiten innerhalb eines einzelnen Projekts, aber keine echte projektuebergreifende Dependency-Aufloesung. Das fuehrt besonders bei extern gelinkten Artefakten dazu, dass Builds formal "up to date" wirken koennen, obwohl eine verlinkte Bibliothek bereits neuer ist.

Der wichtigste praktische Effekt ist:

- `build --all` baut mehrere Projektconfigs nacheinander,
- aber ohne Toposort, ohne semantische Nutzung von `dependencies`,
- und ohne Relink gegen externe Artefakt-Timestamps.

Dadurch koennen abhaengige Targets auf alten Bibliotheksstaenden weiterlaufen.

## Was heute funktioniert

Der inkrementelle Compile-Pfad fuer C/C++-Quellen innerhalb eines Projekts ist grundsaetzlich solide:

- Source-Timestamp wird geprueft in [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L48)
- Compiler-Dependency-Files (`.d`) werden geparst in [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L20)
- Konfigurationsaenderungen triggern Recompile ueber `config_mtime` in [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L44)

Fuer klassische "eine Binary, ihre Sources, ihre Header" ist das ausreichend.

## Wo die Architektur aktuell bricht

### 1. `dependencies` existiert nur im Modell, nicht im Build-Verhalten

Projektabhaengigkeiten sind im Schema vorhanden:

- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py#L80)
- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py#L113)

Aber der Build-Tool-Code verwendet dieses Feld gar nicht:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py)

Es gibt derzeit:

- keine graphbasierte Aufloesung,
- keinen Build-Order-Abgleich,
- keine semantische Zuordnung "Projekt A erzeugt Artefakt X, Projekt B haengt davon ab".

Damit ist `dependencies` momentan eher dokumentativ als funktional.

### 2. `build --all` ist nur eine Sequenz, kein Dependency-Plan

Der `--all`-Pfad entdeckt Configs und baut sie nacheinander:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L247)

Es gibt dort:

- keine Toposort,
- keine Zykluspruefung,
- keine Ableitung eines Buildgraphen,
- keine automatische Wiederholung abhaengiger Targets nach veraenderten Outputs.

Das ist funktional eher "for each config: run build" als echtes Multi-Project-Building.

### 3. Relink-Entscheidungen ignorieren externe Artefakte

Der Relink-Check betrachtet nur die lokalen Objektdateien:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L205)

Wenn keine `.o` neuer als das Output sind, wird das Linken uebersprungen:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L212)

Nicht beruecksichtigt werden dabei:

- Shared Libraries in `linker.library_paths`
- direkt referenzierte Projektartefakte
- externe `.so`/`.a`, gegen die gelinkt wird
- Artefakte anderer Exodus-Projekte

Das ist der praktisch wichtigste Dep-Bug.

### 4. `library_paths` und `libraries` werden nur an den Linker weitergereicht

Die Linker-Konfiguration ist vorhanden:

- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py#L54)

Im Linkschritt werden `-L...` und `-l...` gesetzt:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L223)

Aber daraus wird keinerlei Input-Tracking erzeugt. Fuer das Buildsystem sind diese Libraries aktuell Linker-Flags, nicht Build-Dependencies.

## Konkretes Beispiel: `aiml` und `9rooms`

Im `9rooms`-Projekt zeigen die Configs direkt auf `aiml/out/libaiml`:

- [exodus.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/9rooms/exodus.json)
- [exodus-frontend.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/9rooms/exodus-frontend.json)
- [exodus-client.json](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/9rooms/exodus-client.json)

Gleichzeitig sind die `dependencies` dort leer.

Das fuehrt zu diesem typischen Problemfall:

1. `aiml` wird neu gebaut und erzeugt eine neue `libaiml.so`
2. `9rooms-frontend` hat keine geaenderten `.o`
3. Exodus sagt "up to date, skipping linkage"
4. `9rooms-frontend` laeuft weiter gegen einen alten Linkstand

Selbst wenn zur Laufzeit ueber `rpath` dieselbe Bibliothek gefunden wird, bleibt der Buildstatus aus Sicht von Exodus inkonsistent, weil die externe Artefaktaenderung im Buildgraph nie sichtbar war.

## Wahrscheinlichste Auswirkungen im Alltag

- scheinbar "unerklärliche" Altverhalten nach Bibliotheksaenderungen
- Build laeuft gruen, aber ein abhaengiges Binary spiegelt neue Runtime-Aenderungen nicht sauber
- Unsicherheit, ob ein Projekt wirklich neu gelinkt wurde
- manuelle Komplett-Builds als Workaround
- `--all` erzeugt nur scheinbare Vollstaendigkeit

## Verbesserungsplan

### sprint_task_1: `dependencies` semantisch aktiv machen

Ziel:

- `dependencies` soll nicht nur im Schema existieren, sondern im Buildgraph verwendet werden

Minimum:

- Dependency-Eintraege auf Projektname oder Config-Datei abbilden
- vor `build --all` einen Graphen bilden
- Toposort und Zyklusfehler einfuehren

Betroffene Stellen:

- [project.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/models/project.py)
- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py)

### sprint_task_2: Relink-Inputs fuer externe Artefakte tracken

Ziel:

- Linkage darf nicht nur von `.o`-Timestamps abhaengen

Minimum:

- explizite Liste von Link-Inputs bilden
- Timestamps von `.so`/`.a` mit pruefen
- wenn eine externe Library neuer ist als das Zielartefakt, relinken

Betroffene Stellen:

- [build.py](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/exodus/exodus/tools/build/build.py#L205)

### sprint_task_3: Projektartefakt-Abhaengigkeiten explizit modellieren

Empfehlung:

- zusaetzlich zu `dependencies` ein Feld wie `artifact_dependencies` oder `link_targets`
- damit klar ist, gegen welche Exodus-Projektoutputs relinkt werden muss

Das ist robuster als implizit aus `library_paths` und `libraries` etwas zu erraten.

### sprint_task_4: `build --all` als echten Multi-Project-Build behandeln

Ziel:

- `--all` soll nicht nur alle Configs nacheinander aufrufen
- sondern den Projektgraph respektieren

Optional:

- paralleles Bauen unabhaengiger Knoten
- Wiederanstoessen downstream-abhaengiger Targets bei veraenderten Outputs

## Empfehlung

Der wichtigste erste Fix ist nicht "mehr Dependency-Features" allgemein, sondern ganz konkret:

- Relink gegen externe Artefakte korrekt machen
- und `dependencies` endlich in den Buildpfad integrieren

Solange das fehlt, bleibt Exodus fuer Multi-Project-Setups nur ein Satz einzelner Buildlaeufe, aber kein belastbares abhaengigkeitsgesteuertes Buildsystem.
