# AIML Snapshot-/Memory-Dump-Modus

## Problem

Der aktuelle Debug-Zyklus ist zu teuer:

1. Logs einfuegen
2. neu kompilieren
3. Prozesse neu starten
4. Test manuell fahren
5. Rueckmeldung auswerten
6. wiederholen

Gerade bei Mirror-/Sync-/Runtime-Bugs ist das zu langsam. Man sieht oft erst nach mehreren Iterationen, welcher Teil des Zustands kippt.

## Idee

Ein eigener AIML-Diagnosemodus, der waehrend der Laufzeit fortlaufend lesbare Zustandsabbilder schreibt.

Nicht:

- rohe Debug-Logs an beliebigen Stellen
- staendiges manuelles Instrumentieren

Sondern:

- strukturierte Dumps
- aus vorhandenen Serialisierungs- und Hot-Reload-Bausteinen abgeleitet
- gezielt fuer Modelle, Globals und Mirror-relevante Runtime-Objekte

## Warum das naheliegt

AIML hat dafuer schon wesentliche Grundlagen:

- Serialisierung ist bereits vorhanden
- Mirror braucht strukturierte Zustandsrepraesentationen
- Hot Reload arbeitet bereits mit kompilierten Code-/State-Grenzen
- der Compiler kennt Typen, Modelle, Globals und Symboltabellen

Das heisst: man muss nicht bei null anfangen. Es geht eher darum, vorhandene Runtime-Informationen in einen expliziten Diagnosekanal zu bringen.

## Zielbild

Ein Modus wie:

```text
aiml --snapshot-runtime client/main.aiml
```

oder zur Laufzeit:

```text
AIML_SNAPSHOT_MODE=1
```

Dann schreibt die Runtime in festen Intervallen oder an definierten Hooks Snapshots, zum Beispiel:

- nach jedem `sess.update`
- nach jedem Mirror-Delta
- nach RPC-Empfang
- nach Modell-Mutation
- nach jedem Frame oder Tick

## Form der Ausgabe

Wichtig ist: nicht nur "mehr Logs", sondern lesbare Speicherabbilder.

Beispiel:

```yaml
tick: 1842
source: client/net.aiml
event: mirror.update
objects:
  g_view:
    round: 2
    event_seq: 13
    event_count: 3
    reaction_open: 0
    reaction_kind: ""
    reactable_count: 3
  g_client_info:
    player_name: "nikolai"
    deckset_id: "..."
  g_selected_deckset_id: "..."
```

Alternativ JSON oder NDJSON. Fuer Diffing waere NDJSON oft praktischer.

## Hauptnutzen

Damit koennte man:

- den exakten Zeitpunkt sehen, an dem ein Feld kippt
- server- und clientseitige Snapshots direkt vergleichen
- Mirror-Probleme als State-Diff statt als Textlog lesen
- Tests automatisieren: "Snapshot N muss Feld X = Y enthalten"
- deutlich weniger haendisch instrumentieren

Gerade fuer Bugs wie kaputte `reaction_kind`-Strings waere das viel hilfreicher als verstreute `print`-Zeilen.

## Minimalvariante

Die einfachste brauchbare Version waere kein generischer Memory-Dump, sondern ein fokussierter Runtime-Snapshot-Modus:

- nur registrierte Mirror-Objekte
- nur bekannte Globals
- nur serialisierbare AIML-Typen
- Ausgabe nach bestimmten Triggern

Das waere technisch realistischer als ein kompletter Dump aller LLVM- oder Heap-Strukturen.

## Was vermutlich einfach waere

Relativ gut machbar:

- Modelle mit `sync:`-Feldern dumpen
- AIML-Globals dumpen, wenn sie serialisierbar sind
- Snapshot-Hooks an Stellen wie `mirror.update`, `register_id`, `send_rpc`, `next_event`
- separate Dateien pro Tick oder NDJSON-Stream

Warum:

- diese Objekte sind semantisch ohnehin schon "sichtbarer Zustand"
- sie passen gut zu vorhandenem Serialize-/Mirror-Denken

## Was schwieriger waere

Schwieriger ist ein echter generischer Speicherabbild-Modus:

- beliebige Pointer
- nicht-serialisierbare Runtime-Typen
- rohe interne Container
- fluechtige C++-Objekte ausserhalb des AIML-Modells
- direkte LLVM-nahe Speicherstrukturen

Das waere schnell unlesbar und fragil.

Deshalb sollte das Ziel nicht "alle Bytes dumpen" sein, sondern:

- semantische Zustands-Snapshots
- mit optionalem Raw-Modus nur fuer Spezialfaelle

## Bezug zum Hot Reload

Hot Reload ist hier interessant, weil es bereits ueber stabile Grenzen zwischen:

- Code
- Symbolen
- globalem Zustand
- Reinitialisierung

nachdenken muss.

Ein Snapshot-Modus koennte davon profitieren:

- dieselben bekannten Globals/Symbole enumerieren
- denselben Typkontext nutzen
- dieselben registrierten Modelle adressieren

Ich wuerde das aber trotzdem als separates Diagnosefeature behandeln und nicht zu eng an Hot Reload koppeln.

## Konkreter Vorschlag

### Phase 1: Mirror-Snapshot-Modus

Ein fokussierter Modus nur fuer Mirror-Debugging:

- dump clientseitige Replica-Objekte
- dump serverseitige Originalobjekte
- dump relevante Globals
- schreibe Snapshots vor und nach `sess.update`

Das wuerde aktuelle Debug-Zyklen sofort beschleunigen.

### Phase 2: Runtime-Snapshot-API

Eine kleine Runtime-API wie:

```text
snapshot.dump("after_update")
snapshot.dump_obj("view", g_view)
snapshot.dump_var("selected_deckset", g_selected_deckset_id)
```

Dann koennen Tests und Runtime dieselbe Mechanik nutzen.

### Phase 3: Compiler-unterstuetzte Auto-Snapshots

Ein Compiler-Flag, das bestimmte Hooks automatisch instrumentiert:

- nach `set` auf `sync:`-Modelle
- nach `mirror.update`
- nach `register`
- nach `register_id`

Dann muss man nicht mehr manuell Logs einfuegen.

## Format-Empfehlung

Ich wuerde mit NDJSON anfangen:

- einfach zu schreiben
- einfach zu diffen
- einfach mit `rg`, `jq` oder Python auszuwerten
- gut fuer lange Laeufe

Beispiel:

```json
{"tick":1842,"side":"client","event":"mirror.update.after","view":{"event_seq":13,"reaction_kind":"","reactable_count":3}}
```

## Warum das besser ist als der jetzige Prozess

Der jetzige Prozess ist:

- langsam
- invasiv
- stark manuell
- schwer reproduzierbar

Ein Snapshot-Modus waere:

- schneller
- vergleichbarer
- testbarer
- naeher an der eigentlichen State-Maschine des Systems

## Empfehlung

Ja, so ein Modus ist sinnvoll und wahrscheinlich deutlich wertvoller als noch mehr ad-hoc-Logs.

Wichtig ist aber die Zielschärfe:

- nicht "beliebige Speicherabbilder"
- sondern "lesbare semantische Zustands-Snapshots"

Fuer AIML wuerde ich mit einem Mirror-/Runtime-Snapshot-Modus anfangen, weil dort der aktuelle Schmerz am groessten ist und bereits die meisten strukturierten Daten vorliegen.

## Technischer Entwurf

### Betroffene C++-Dateien

Die sinnvollsten Einstiegspunkte im aktuellen AIML-Code sind:

- [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp)
  Dort sitzen die Mirror-Lifecycle-Hooks wie `aiml_mirror_session_update`, `register`, `register_id`, `next_event` und `send_rpc`.
- [mirror_runtime.h](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.h)
  Fuer die Runtime-API des Snapshot-Modus.
- [serialize_impl.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/serialize_impl.cpp)
  Vorhandene Struktur-Serialisierung kann fuer lesbare Snapshot-Payloads wiederverwendet werden.
- [builtin_registry.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/builtin_registry.cpp)
  Wenn eine AIML-seitige API wie `snapshot.dump(...)` angeboten werden soll.
- [context.h](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/context.h)
  Dort liegen bereits Typinfos, Klasseninfos und Mirror-Metadaten wie `sync`-/`rpc`-Felder.

### Warum gerade dort

Im Mirror-Pfad sind die wichtigsten Hooks schon zentralisiert:

- `aiml_mirror_session_update(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L794)
- `aiml_mirror_session_register(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L828)
- `aiml_mirror_session_register_id(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L837)
- `aiml_mirror_session_register_id_typed(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L915)
- `aiml_mirror_session_next_event(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L1005)
- `aiml_mirror_session_send_rpc(...)` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L1084)

Das ist genau der Pfad, in dem der aktuelle Debug-Bedarf am groessten ist.

### Vorschlag fuer neue Runtime-Komponente

Neue Datei:

- `src/sys/snapshot_runtime.{h,cpp}`

Aufgaben:

- Modus per Env oder API aktivieren
- Snapshot-Output-Datei verwalten
- NDJSON schreiben
- Hilfsfunktionen fuer Strings, Events und strukturierte Payloads anbieten

Minimale API:

```cpp
void aiml_snapshot_init_from_env(void);
void aiml_snapshot_emit_json_line(const char* json_line);
void aiml_snapshot_emit_kv(const char* phase, const char* side, const char* event, const char* payload_json);
int  aiml_snapshot_enabled(void);
```

Optional spaeter:

```cpp
void aiml_snapshot_emit_model(const char* phase, const char* side,
                              const char* event, int32_t net_id,
                              const char* type_name, const char* json_payload);
```

### Empfohlene Aktivierung

Zunaechst nur per Environment:

```text
AIML_SNAPSHOT_MODE=1
AIML_SNAPSHOT_FILE=/tmp/aiml_snapshot.ndjson
AIML_SNAPSHOT_SIDE=client
```

Optional:

```text
AIML_SNAPSHOT_FILTER=mirror.update,register_id,next_event
```

Das ist einfacher als sofort neue CLI-Syntax durch den ganzen Compiler zu ziehen.

## Hook-Punkte

### Phase 1: Mirror-Runtime Hooks

Ich wuerde zuerst nur diese Hooks instrumentieren:

- vor `aiml_mirror_session_update(...)`
- nach `aiml_mirror_session_update(...)`
- nach `aiml_mirror_session_register_id(...)`
- nach `aiml_mirror_session_register_id_typed(...)`
- direkt in `aiml_mirror_session_next_event(...)`
- direkt in `aiml_mirror_session_send_rpc(...)`

Nutzen:

- man sieht den Zustand genau an den Uebergaengen, an denen sich Replica-State aendert
- keine breite Instrumentierung im restlichen Compiler noetig

### Konkrete Snapshots an diesen Hooks

`update.before`

- Session-Zustand
- Queue-Laengen
- bekannte registrierte Net-IDs

`update.after`

- dasselbe erneut
- plus Snapshots der registrierten typed objects

`register_id.after`

- net_id
- obj_size
- ob typed oder untyped
- initialer Objekt-Snapshot

`next_event`

- Event-Typ
- net_id
- Peer-ID
- Queue-Status vor/nach Pop

`send_rpc`

- net_id
- method
- arg_kind
- arg oder Modell-Blob-Laenge

## Was genau gesnapshottet werden sollte

### Session-Metadaten

Aus `AimlMirrorSession` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L121):

- `is_host`
- `next_net_id`
- Anzahl `peers`
- Anzahl `by_net_id`
- Anzahl `event_queue`
- Anzahl `rpc_queue`

### Registrierte Mirror-Objekte

Aus `AimlMirrorRegistered` in [mirror_runtime.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/sys/mirror_runtime.cpp#L86):

- `net_id`
- `obj_size`
- `is_owner`
- `manual_sync`
- `has_decoded`
- typed/untyped

Und fuer typed Objekte zusaetzlich:

- serialisierte JSON-Darstellung des aktuellen Objekts

### Mirror-Events

Aus `AimlMirrorEvent`:

- `type`
- `net_id`
- `peer_id`

### RPC-Events

Aus `AimlRpcEvent`:

- `method`
- `net_id`
- `arg_kind`
- `arg`
- `arg_blob_len`

## Wie der Objekt-Snapshot erzeugt werden kann

### Typed Mirror-Objekte

Das ist der wichtigste Fall und auch der realistischste.

Wenn `AimlMirrorRegistered.ser_nodes != nullptr`, dann hat das Objekt bereits typisierte Serialisierungsmetadaten. Genau dort sollte der Snapshot-Modus ansetzen.

Pragmatischer Weg:

1. neue Runtime-Hilfe in `ser_runtime.cpp` oder `snapshot_runtime.cpp`
2. typed Objekt ueber vorhandene Ser-Information in JSON umwandeln
3. Ergebnis als String in NDJSON schreiben

Das ist besser als rohe Bytes.

### Untyped Objekte

Fuer untyped Registrierungen zunaechst nur Metadaten dumpen:

- `net_id`
- `obj_size`
- hex preview der ersten N Bytes

Das reicht fuer Phase 1.

## NDJSON-Schema

Ich wuerde bewusst klein anfangen.

Beispiel:

```json
{
  "ts_ms": 1712460734123,
  "side": "client",
  "phase": "update.after",
  "event": "mirror_session_update",
  "session": {
    "is_host": 0,
    "peer_count": 1,
    "registered_count": 2,
    "event_queue_count": 0,
    "rpc_queue_count": 0
  },
  "objects": [
    {
      "net_id": 1,
      "typed": true,
      "owner": false,
      "type_name": "GameView",
      "json": {
        "event_seq": 13,
        "event_count": 3,
        "reaction_open": 0,
        "reaction_kind": "",
        "reactable_count": 3
      }
    }
  ]
}
```

Minimaler Pflichtsatz:

- `ts_ms`
- `side`
- `phase`
- `event`

Der Rest kann je nach Hook variieren.

## Compiler-seitige Erweiterung spaeter

Wenn Phase 1 funktioniert, kann man eine AIML-API dazunehmen.

Beispiel:

```yaml
- call: [snapshot.dump, "after_update"]
- call: [snapshot.dump_obj, "view", g_view]
```

Dafuer waeren Anpassungen in [builtin_registry.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/builtin_registry.cpp) noetig.

Zuerst wuerde ich das aber vermeiden und nur die Runtime-Hooks bauen. Sonst landet man wieder bei einem groesseren Compiler-Thema, bevor der erste Nutzen da ist.

## Grobe Implementierungsreihenfolge

1. `snapshot_runtime.{h,cpp}` anlegen
2. Env-basierte Aktivierung und NDJSON-Writer bauen
3. `mirror_runtime.cpp` an den sechs Hook-Punkten instrumentieren
4. Session-Metadaten plus Event-/RPC-Dumps ausgeben
5. typed Mirror-Objekte als JSON-Snapshots ausgeben
6. erst danach AIML-API oder Auto-Instrumentierung im Compiler diskutieren

## Risikoabschaetzung

Niedriges Risiko:

- NDJSON-Writer
- Mirror-Hooks
- Session-/Event-Metadaten

Mittleres Risiko:

- typed Objekt-JSON zur Laufzeit stabil und billig erzeugen

Hoeheres Risiko:

- generische Snapshots fuer beliebige nicht-typed Objekte
- automatische Compiler-Instrumentierung auf `set`-/`sync:`-Mutationsebene

## Meine Empfehlung

Nicht sofort einen allumfassenden Snapshot-Modus bauen.

Stattdessen:

- Mirror-Runtime zuerst
- typed Registrierungen zuerst
- NDJSON zuerst
- keine neue AIML-Syntax in Phase 1

Damit bekommt man relativ schnell ein Werkzeug, das fuer den aktuellen `reaction_kind`-/Mirror-State-Bug deutlich nuetzlicher ist als der jetzige Log-und-Neustart-Zyklus.
