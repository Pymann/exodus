# AIML Import- und Test-Architektur

## Ausgangslage

Der aktuelle Fix fuer die Import-Aufloesung im AIML-Compiler funktioniert, ist aber semantisch unscharf:

- ein `import` kann implizit ueber `cwd` aufgeloest werden
- wenn das fehlschlaegt, wird relativ zur aktuell kompilierenden Datei nach oben gelaufen
- bei verschachtelten Imports veraendert sich das Suchverhalten dynamisch ueber `currentSourceFile`
- dieselbe `import`-Syntax wird fuer Produktions-Code, transitive Abhaengigkeiten und testartige Ersatzverdrahtung verwendet

Das loest akute Probleme, macht aber das System schwer vorhersagbar:

- derselbe Code kann je nach Startverzeichnis andere Dateien finden
- die Suchstrategie ist fuer Nutzer nicht im Code sichtbar
- ein Import kann unbeabsichtigt eine gleichnamige Datei aus einem uebergeordneten Verzeichnis ziehen
- Integrations- und Test-Faelle brauchen andere Semantik als normaler Produktions-Import
- auch fuer KI-gestuetzte Analyse, Refactorings und Testgenerierung ist das Verhalten schwer zu modellieren, weil die Aufloesung nicht lokal aus dem AIML-Code selbst ableitbar ist

## Zielbild

Das Import-System sollte:

- explizit statt heuristisch sein
- zwischen Produktions-Abhaengigkeit und Test-Ersatz unterscheiden
- statisch nachvollziehbar bleiben
- fuer Unit- und Integrationstests eigene, kontrollierte Mechanismen bieten
- Mocking und Stubbing nicht ueber Dateisystem-Zufall, sondern ueber Sprach- und Compiler-Features loesen

## Bewertung des aktuellen Fixes

Positiv:

- bestehender Code laeuft weiter
- 9rooms-artige transitive Imports funktionieren robuster
- verschachtelte Imports werden nicht mehr nur relativ zum Prozess-`cwd` aufgeloest

Negativ:

- Aufloesungsregeln sind im AIML-Code nicht sichtbar
- die Semantik ist implizit zustandsbehaftet (`currentSourceFile`)
- "walk up and probe" kann ueberraschende Treffer produzieren
- Fehleranalyse wird schwieriger, weil nicht klar ist, warum genau eine bestimmte Datei gefunden wurde
- das ist ein schlechter Grundstein fuer einen sauberen Test-Stack
- auch statische Werkzeuge und KI-Assistenten koennen Importbeziehungen nur unzuverlaessig rekonstruieren, weil sie dafuer Laufzeitkontext, Arbeitsverzeichnis und implizite Compilerzustandswechsel kennen muessen

## Zusatzproblem: schlechte Verstehbarkeit fuer KI und Tools

Der aktuelle Mechanismus ist nicht nur fuer Menschen intransparent, sondern auch fuer KI-basierte Entwicklungswerkzeuge besonders unguenstig.

Probleme:

- aus einem einzelnen AIML-File ist nicht eindeutig ablesbar, welche Datei ein `import` effektiv meint
- die Aufloesung haengt von verstecktem Kontext ab: aktuelle Quelldatei, Aufrufort des Compilers, vorhandene Verzeichnisstruktur und rekursive Zustandsaenderungen
- fuer Refactoring-Tools ist nicht stabil entscheidbar, welche Datei bei einer Umbenennung oder Verschiebung betroffen ist
- fuer KI-generierte Tests oder Mocks ist nicht klar, welches Modul tatsaechlich ersetzt werden muss
- auch Dokumentation, Architektur-Analyse und Dead-Code-Erkennung werden unzuverlaessiger

Folge:

- die Semantik ist nicht gut maschinenlesbar
- sie ist nicht sauber indexierbar
- sie ist fuer automatische Code-Navigation und fuer KI-Assistenz deutlich schlechter geeignet als ein explizites, deklaratives Importsystem

Gerade wenn AIML staerker mit KI-gestuetzten Workflows verwendet werden soll, ist Determinismus nicht nur ein Build-Thema, sondern auch ein Verstehbarkeits- und Werkzeugthema.

## Vorschlag 1: Import-Arten explizit machen

Das nackte `import` sollte auf einen klaren, engen Mechanismus reduziert werden. Fuer verschiedene Faelle sollte es verschiedene Formen geben.

Beispiel:

```yaml
- import:
    path: "shared/mirror_helpers.aiml"
    kind: "relative"
```

Moegliche `kind`-Werte:

- `relative`: relativ zur importierenden Datei, ohne Upward-Search
- `project`: relativ zu einer expliziten Projektwurzel oder konfigurierten Import-Root
- `package`: spaeter fuer wiederverwendbare AIML-Pakete
- `test_double`: nur in Test-Builds erlaubt

Regel:

- kein stilles Fallback auf `cwd`
- kein automatisches Hochlaufen im Verzeichnisbaum als Default
- wenn Aufloesung fehlschlaegt, harter und gut erklaerter Compilerfehler

## Vorschlag 2: Import-Roots explizit konfigurieren

Wenn mehrere Module wie `9rooms/client`, `9rooms/shared`, `9rooms/frontend` zusammenarbeiten, sollte das nicht ueber Suchheuristiken passieren, sondern ueber deklarierte Roots.

Beispiel in Compiler- oder Projekt-Config:

```yaml
import_roots:
  - "."
  - "./shared"
  - "./frontend"
  - "./client"
```

Dann gilt:

- `kind: relative` nutzt nur die importierende Datei
- `kind: project` sucht nur in `import_roots` in definierter Reihenfolge
- der Compiler gibt auf Wunsch im Diagnosemodus den exakten Match-Pfad aus

Das ist transparent und reproduzierbar.

## Vorschlag 3: Test-Build als eigenes Konzept

Der Compiler sollte einen echten Test-Modus kennen, statt Tests nur als normale Programme zu behandeln.

Beispiel:

```yaml
- test:
    name: "mirror ws imports"
    mode: "integration"
```

Oder ueber Build-Flag:

```text
aiml --test tests/test_mirror_ws_9rooms_imports.aiml
```

Im Test-Modus sind dann eigene Sprachfeatures erlaubt:

- `test_import`
- `mock`
- `stub`
- Assertions und Test-Fixtures
- kontrollierte Override-Regeln

Der Produktions-Compiler bleibt damit einfacher und strenger.

## Vorschlag 4: Eigenes Test-Import-Statement

Wenn ein Test absichtlich eine andere Implementierung ziehen soll, sollte das im Code klar erkennbar sein.

Beispiel:

```yaml
- test_import:
    target: "shared/payment.aiml"
    with: "tests/doubles/payment_stub.aiml"
```

Semantik:

- nur im Test-Modus erlaubt
- ersetzt exakt ein Zielmodul
- Compiler prueft Typ-/Signatur-Kompatibilitaet
- Build-Output dokumentiert die aktive Ersetzung

Das ist deutlich besser als "gleichnamige Datei irgendwo im Suchpfad".

## Vorschlag 5: Mock- und Stub-Generierung im Compiler

Statt Doubles komplett manuell zu schreiben, kann der Compiler aus einem Modul oder Interface Test-Doubles erzeugen.

### 5.1 Stub-Generierung

Ziel:

- feste Rueckgaben
- keine Seiteneffekte
- einfache Integrationstests

Beispiel:

```yaml
- generate_stub:
    from: "shared/payment.aiml"
    out: "tests/generated/payment_stub.aiml"
```

Der Compiler koennte:

- alle exportierten Funktionen spiegeln
- Default-Rueckgaben erzeugen
- Modelle/Enums uebernehmen
- fuer `extern` oder globale Symbole neutrale Testvarianten erzeugen

### 5.2 Mock-Generierung

Ziel:

- Aufrufe aufzeichnen
- Erwartungen pruefen
- Rueckgaben gezielt konfigurieren

Beispiel:

```yaml
- generate_mock:
    from: "shared/payment.aiml"
    out: "tests/generated/payment_mock.aiml"
```

Zusaetzliche Compiler-Hilfen:

- automatisch generierte Call-Log-Strukturen
- `mock.expect_called`
- `mock.expect_not_called`
- `mock.set_return`

### 5.3 Praktische Machbarkeit im aktuellen C++-Compiler

Nuechtern betrachtet ist Stub-Generierung im aktuellen Code deutlich einfacher als echte Mock-Generierung.

Relativ einfach:

- Funktionssignaturen liegen nach dem Parse bereits strukturiert vor und werden in `registerTypeDecl(...)` und `visitFunction(...)` verarbeitet, siehe [compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/compiler.cpp#L217) und [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L933)
- Typen, Modelle und Enums werden ohnehin vorab registriert, also kann man fuer ein Stub-Modul die oeffentliche Form eines importierten Moduls grundsaetzlich schon ableiten, siehe [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L466)
- fuer reine Funktionsmodule ohne globale mutable States waere ein generierter Stub im Wesentlichen nur ein zweites AIML-AST oder direkt erzeugtes IR mit Default-Rueckgaben

Mittelschwer:

- importierte Module laufen in `libraryMode` und bekommen eigene `__aiml_lib_init_*`-Funktionen, die vor Top-Level-Code des Hauptmoduls ausgefuehrt werden, siehe [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L24) und [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L172)
- ein Stub fuer ein Modul mit Top-Level-Initialisierung muesste diese Init-Semantik kompatibel nachbilden, sonst veraendert sich das Verhalten gegenueber dem echten Modul
- fuer globale Decl-Stmts erzeugt der Compiler echte LLVM-Globals und traegt sie sofort in `ctx.symbol_table` ein, siehe [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L53) und [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L93)

Schwierig:

- die Symbolbindung ist aktuell stark datei- und zustandsabhaengig: `resolveImportCallback`, `currentSourceFile`, `libInitFuncNames`, `symbol_table` und sibling injection greifen ineinander, siehe [compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/compiler.cpp#L145) und [compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/compiler.cpp#L357)
- ein Mock, der nur einzelne Funktionen ersetzen soll, braucht heute keine saubere Modulgrenze, sondern muss effektiv dieselben Symbolnamen, Globals und Initialisierungsreihenfolgen treffen wie das Original
- `extern`-Globals werden absichtlich ueber plain `__lib_<name>` zusammengefuehrt, nicht-`extern`-Globals ueber dateinamenspezifische Symbole; ein generierter Mock muesste genau diese Regeln treffen, sonst entstehen stille Link- oder Laufzeitabweichungen, siehe [ast_compiler.cpp](/media/nikolai/95a208ef-ffa2-478b-abdd-ff394baa6a76/projects/python/test/aiml/src/core/ast_compiler.cpp#L68)
- weil sehr viel ueber `ctx.symbol_table` aufgeloest wird, ist teilweises Ersetzen eines Moduls schwieriger als komplettes Ersetzen eines Imports

Konsequenz:

- Stub-Generierung fuer einfache, eher funktionale Module ist machbar
- Mock-Generierung fuer Module mit Globals, Top-Level-Code, `extern`-State und mehreren sibling imports ist im aktuellen Compiler eher aufwendig
- wirkliche Mock-Unterstuetzung wird deutlich einfacher, wenn AIML zuerst explizitere Modulvertraege und strengere Import-Semantik bekommt

## Vorschlag 6: Sprachliche Trennung zwischen API und Implementierung

Mocking wird einfacher, wenn AIML sauber zwischen Vertrag und Implementierung trennt.

Empfehlung:

- explizite Modul-API oder Interface-Dateien
- Implementierungen binden gegen einen Vertrag, nicht direkt gegen konkrete Dateien

Beispielrichtung:

```yaml
- import:
    path: "shared/payment.api.aiml"
    kind: "project"
```

Und dann im Produktions- oder Test-Build:

- echte Implementierung bindet `payment.api`
- Test bindet `payment.mock`

Das ist architektonisch sauberer als globale Dateiersetzung.

## Vorschlag 7: Overrides auf Modulebene statt Dateisystemebene

Der Compiler oder Build-Driver sollte Modul-Overrides explizit annehmen koennen.

Beispiel:

```text
aiml --override shared/payment.aiml=tests/doubles/payment_stub.aiml
```

Oder in einer Test-Datei:

```yaml
- test_overrides:
    "shared/payment.aiml": "tests/doubles/payment_stub.aiml"
    "client/api.aiml": "tests/doubles/api_mock.aiml"
```

Vorteile:

- voll reproduzierbar
- CI-freundlich
- gut loggbar
- keine impliziten Suchpfad-Nebenwirkungen

## Vorschlag 8: Compiler-Diagnostik fuer Import-Aufloesung

Unabhaengig von der finalen Syntax sollte der Compiler einen transparenten Diagnosemodus bekommen.

Beispiel:

```text
aiml --trace-imports client/main.aiml
```

Ausgabe:

- welche Datei importiert wen
- nach welcher Regel wurde aufgeloest
- welche Kandidaten wurden verworfen
- welche Test-Overrides oder Doubles waren aktiv

Das waere sofort nuetzlich, auch schon vor einer groesseren Sprachreform.

## Vorschlag 9: Test-Pyramide fuer AIML

Die Sprache braucht wahrscheinlich drei Test-Ebenen.

### 9.1 Compiler-Unit-Tests

Ziel:

- Parser
- Import-Aufloesung
- Symbolbindung
- Typpruefung
- Mock-/Stub-Kompatibilitaet

Form:

- kleine AIML-Dateien
- erwartete Compilerdiagnosen
- IR- oder Symboltabellen-Checks

### 9.2 Modul-Tests

Ziel:

- einzelnes AIML-Modul gegen Stubs oder Mocks
- keine echte Infrastruktur

Form:

- `test_import` oder `--override`
- Assertions auf Rueckgaben, Modellzustand, Call-Logs

### 9.3 Integrations-Tests

Ziel:

- echte Module zusammen
- echte mirror/ws/db-Flows

Form:

- moeglichst wenig Overrides
- echte Cross-Module-Interaktion
- eher Szenario-Tests als kleinteilige Mocks

9rooms `mirror sync` gehoert klar in diese Ebene.

## Konkrete Empfehlung

Ich wuerde nicht weiter auf den aktuellen "walk up and probe"-Mechanismus setzen. Stattdessen:

1. Kurzfristig:
   `--trace-imports` und harte Logging-Ausgabe fuer Aufloesungsentscheidungen einfuehren.

2. Mittelfristig:
   `import.kind` plus explizite `import_roots` einfuehren.

3. Fuer Tests:
   `test_import` oder `--override` als offiziellen Mechanismus bauen.

4. Danach:
   Mock-/Stub-Generierung auf Basis von Modul-APIs oder Interfaces einfuehren.

## Minimaler Migrationspfad

Ein realistischer Weg ohne Big Bang:

### Phase 1

- aktuellen Mechanismus beibehalten
- aber Warning ausgeben, wenn Upward-Search verwendet wurde
- `--trace-imports` implementieren

### Phase 2

- neue Syntax `import: { path, kind }`
- alte Stringform weiter unter Deprecation

### Phase 3

- `test_import` und `--override`
- erste Stub-Generierung fuer einfache Funktionsmodule

### Phase 4

- API-/Interface-basierte Mock-Generierung
- alte implizite Heuristik entfernen

## Fazit

Der aktuelle Fix ist als Notfallmassnahme verstaendlich, aber als langfristige Semantik zu implizit. Fuer AIML waere ein explizites Modulsystem mit eigenem Test-Overlay deutlich besser als dateisystembasierte Suchheuristik.

Die wichtigste Designentscheidung ist aus meiner Sicht:

- Produktions-Imports muessen deterministisch und streng sein
- Test-Ersetzungen muessen explizit und sprachlich sichtbar sein
- die Import-Semantik sollte so lokal und deklarativ sein, dass auch KI-Tools, Indexer und Refactoring-Werkzeuge sie ohne versteckten Laufzeitkontext verstehen koennen

Dann werden sowohl 9rooms-Integrationsfaelle als auch spaetere Unit-Tests deutlich sauberer.
