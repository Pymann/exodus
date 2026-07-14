# Exodus Asset Management

## Ziel

Dieses Dokument beschreibt, ob und wie `exodus` langfristig ein Asset-Management
fuer Spiele und andere Anwendungen tragen koennte.

Der Fokus liegt bewusst auf:

- Machbarkeit
- Architektur
- Paket- und Abhaengigkeitsmodell
- Asset-Formate und Verpackung
- Rolle von Python

Nicht im Vordergrund stehen hier:

- konkrete Implementierungsdetails
- sofortige CLI-Befehle
- erste Codeaenderungen

## Kurzfazit

Ja, `exodus` koennte theoretisch ein brauchbares Asset-Management-System
bekommen.

Die vorhandene Basis ist bereits teilweise da:

- Projektkonfigurationen
- Paketdefinitionen
- Conan-Integration
- Build- und Cache-Strukturen
- einfache Abhaengigkeitssicht

Was heute noch fehlt, ist nicht die grundsaetzliche technische Moeglichkeit,
sondern eine eigene **Asset-Schicht** ueber dem bisherigen Paket- und
Buildsystem.

`Conan` kann dabei ein sinnvoller Transport- und Versionskanal sein,
aber `exodus` braucht zusaetzlich ein eigenes Modell fuer:

- Assetpakete
- Assettypen
- Asset-Metadaten
- Staging/Deployment
- Laufzeitverwendung

## Was heute schon vorhanden ist

Im aktuellen `exodus`-Stand gibt es bereits:

- Projektkonfiguration mit Paketlisten
- `conan_packages`
- `apt_packages`
- Cache-Verzeichnislogik
- Paketinstallation ueber Python
- Auswertung installierter Conan-Artefakte fuer Include-/Lib-Pfade
- Buildlogik mit Projektkonfigurationen

Das zeigt:

- `exodus` hat bereits einen Begriff von externen Artefakten
- `exodus` hat bereits einen Cache
- `exodus` hat bereits deklarative Paketlisten

Damit ist die Schwelle zu einem Asset-System deutlich niedriger, als wenn
all das fehlen wuerde.

## Was fuer Asset-Management noch fehlt

Die vorhandene Struktur ist aktuell stark auf C/C++-Build-Artefakte ausgelegt.

Insbesondere fehlt ein explizites Modell fuer:

- Dateien, die keine Header oder Libraries sind
- Runtime-Assets
- platform-spezifische Asset-Transformationen
- Asset-Staging
- Asset-Manifeste
- Asset-Hashes
- Asset-Bundles

Mit anderen Worten:

`exodus` kennt derzeit eher:

- "welche Bibliotheken brauche ich zum Bauen?"

aber noch nicht:

- "welche Assets brauche ich zur Laufzeit?"
- "wo sollen diese Assets im finalen Paket landen?"
- "in welchem Format sollen sie deployt werden?"

## Rolle von Conan

`Conan` kann fuer Asset-Management sinnvoll sein, aber nicht als alleinige
Loesung.

### Was Conan gut kann

- Versionierung
- Paketierung
- Remote-Distribution
- Abhaengigkeiten zwischen Paketen
- reproduzierbare Referenzen

Das ist auch fuer Assets attraktiv:

- z. B. ein Paket mit Texturen
- ein Paket mit Audio
- ein Paket mit Shadern
- ein Paket mit UI-Themes

### Was Conan nicht automatisch loest

- wie Assets zur Laufzeit organisiert werden
- welche Dateien eines Pakets relevante Assets sind
- wohin sie im finalen Build kopiert werden
- ob sie vorab transformiert oder komprimiert werden
- wie sie in Game- oder App-Runtime geladen werden

Darum waere die richtige Sicht:

- `Conan` als Paket- und Versionslayer
- `Exodus` als Asset-Orchestrierungsschicht

## Welche Arten von Assets denkbar sind

Ein Asset-System in `exodus` sollte nicht auf PNGs begrenzt sein.

Sinnvolle Kategorien:

- Bilder
  - PNG
  - JPG
  - SVG
  - GPU-nahe Texturformate
- Audio
  - WAV
  - OGG
  - MP3
- Fonts
  - TTF
  - OTF
- Shader
  - GLSL
  - SPIR-V
  - HLSL-Quellen oder Outputs
- Daten
  - JSON
  - YAML
  - CSV
  - Binärdaten
- Game-spezifische Bundles
  - Kartenbilder
  - Deckdefinitionen
  - VFX
  - UI-Skins

## Asset-Pakete vs. Asset-Dateien

Ein wichtiger Architekturpunkt ist die Trennung zwischen:

1. **Asset-Paket**
   - deklarative Abhaengigkeit in der Projektkonfiguration
   - kann aus Conan oder anderer Quelle kommen

2. **Asset-Datei**
   - konkrete PNG, WAV, JSON, ...
   - liegt im Paket oder im lokalen Projekt

3. **Asset-Bundle**
   - daraus gebautes Laufzeitartefakt
   - z. B. Verzeichnis, ZIP, custom packfile, APK-assets

Ein gutes System muss alle drei Ebenen kennen.

## Kann Python das leisten?

Ja.

Python ist fuer so ein System gut geeignet, weil es stark ist bei:

- Orchestrierung
- Dateiverarbeitung
- Manifest-Erzeugung
- Paketentpackung
- Prozesssteuerung
- Hashing
- Metadatenaggregation

### Python ist gut fuer

- Asset-Scans
- Copy-/Stage-Pipelines
- Hash-/Digest-Berechnung
- JSON-/YAML-Manifeste
- ZIP-/Archiv-Erzeugung
- Conan- und Tool-Aufrufe
- Plattform-spezifische Pipeline-Steuerung

### Python ist weniger ideal fuer

- maximale Kompression allein aus eigener Implementierung
- GPU-spezifische Offline-Konvertierung ohne externe Tools
- Android-Signing und spezialisierte Endformate komplett ohne Toolchain

Darum ist der pragmatische Weg:

- Python orchestriert
- Spezialtools machen die schwere Transformation

## PNG und Kompression

### Fall 1: PNG bleibt PNG

Wenn PNG-Dateien nur optimiert werden, z. B. durch:

- bessere Deflate-Kompression
- Metadaten-Entfernung
- verlustfreie PNG-Optimierung

dann bleibt das Ergebnis weiterhin ein normales PNG.

Vorteil:

- bestehende Loader koennen es weiter lesen
- kein neues Laufzeitformat noetig

### Fall 2: PNG wird in ein Asset-Paket gepackt

Dann bleibt das Bildformat zwar PNG, aber die Runtime braucht:

- Entpacker
- oder einen Asset-Loader, der aus einem Paket lesen kann

Hier entsteht also eine neue Laufzeitanforderung.

### Fall 3: PNG wird in ein anderes Texturformat umgewandelt

Dann ist es nicht mehr einfach "ein PNG".

Beispiele:

- KTX
- ASTC
- ETC2
- Basis/Transcoder-Varianten

Dann muss die Runtime dieses neue Format explizit verstehen.

## Android / APK

Auch fuer Android ist Python als Pipeline-Orchestrator geeignet.

Wichtig ist aber:

- eine APK ist nicht nur "ein ZIP"
- fuer echte Android-Pakete braucht man die Android-Toolchain

Python kann hier sehr gut:

- Assets vorbereiten
- Assets optimieren
- Verzeichnisse strukturieren
- Manifeste erzeugen
- Build-Schritte aufrufen

Der finale Android-konforme Schritt braucht aber typischerweise weiterhin:

- `aapt2`
- `zipalign`
- `apksigner`
- evtl. Gradle

## Was AIML bzw. Runtime davon haette

Wenn `exodus` Asset-Management baut, ist die naechste Frage:

- wie konsumiert die Runtime diese Assets?

Es gibt grob drei Moeglichkeiten:

1. **Dateibasiert**
   - Assets liegen nach dem Build einfach als Dateien vor
   - Runtime laedt wie bisher per Pfad

2. **Bundle-basiert**
   - Assets liegen in einem Archiv oder Packfile
   - Runtime braucht Loader/Entpacker

3. **Memory-/Blob-basiert**
   - Assets werden zur Laufzeit aus Bytes extrahiert
   - Runtime braucht `load_*_from_bytes(...)`

Fuer den Einstieg waere dateibasiertes oder staged Asset-Management deutlich
einfacher als sofort ein eigenes Bundleformat.

## Sinnvolle Architektur fuer Exodus

Ein zukunftsfaehiger Aufbau waere:

### 1. Deklarative Projektkonfiguration

Zusatzfelder wie:

- `asset_packages`
- `asset_roots`
- `asset_rules`
- `bundle_rules`

### 2. Asset-Resolver

Loest auf:

- lokale Assets
- Conan-basierte Assetpakete
- Versionsstaende
- Plattformfilter

### 3. Asset-Manifest

Erzeugt pro Build ein Manifest mit:

- Quelle
- Typ
- Hash
- Zielpfad
- Bundle-Zugehoerigkeit
- optional Kompressions-/Transformationsinfos

### 4. Asset-Staging

Schreibt die finalen Runtime-Assets in:

- `out/<project>/assets/`
- oder in Plattformziele wie:
  - `apk/assets/...`
  - `bundle/...`

### 5. Optionale Bundle-Schicht

Spaeter:

- ZIP
- custom packfile
- Content-addressed bundles

## Denkbare Konfigurationsrichtung

Noch ohne Endschema koennte die Richtung etwa sein:

- Paketquelle
  - lokal
  - Conan
- Assettyp
  - texture
  - audio
  - data
  - font
- Ziel
  - runtime path
  - bundle name
- Regeln
  - include/exclude globs
  - platform filter
  - optimize/compress yes/no

Wichtig ist:

Das sollte nicht still in `conan_packages` hineingepresst werden.

Besser:

- entweder eigener `asset_packages`-Block
- oder generischer `artifacts`-/`resources`-Block

## Grenzen und Risiken

Ein Asset-System hat schnell mehr Komplexitaet als ein normaler Compiler-Build.

Typische Risiken:

- Plattformunterschiede
- uneinheitliche Toolverfuegbarkeit
- unklare Laufzeitpfade
- grosse Datenmengen
- inkonsistente Bundle-/Manifest-Versionen
- schwerer Debug bei "Datei da, aber nicht ladbar"

Darum sollte `exodus` zuerst klein anfangen:

- Datei-Staging
- Hash-/Manifest-Schicht
- Conan-Assetpakete als Quelle

und erst spaeter:

- aggressive Transformation
- eigenes Bundleformat
- plattformspezifische Spezialpipelines

## Realistischer Einstieg

Ein pragmatischer erster Ausbau waere:

1. Conan-Pakete duerfen auch Assets enthalten
2. `exodus` kann diese Assets in einen Cache holen
3. Projekt konfiguriert, welche Assetpfade daraus relevant sind
4. `exodus` staged sie nach `out/.../assets`
5. `exodus` erzeugt ein Manifest

Das wuerde bereits viel Nutzen bringen, ohne sofort Runtime-Bundles oder
Android-Spezialformate vorauszusetzen.

## Schlussfolgerung

`Exodus` hat dafuer eine brauchbare Basis, aber noch kein echtes
Asset-Management.

Der richtige Weg ist:

- `Conan` fuer Paketierung und Versionierung nutzen
- `Exodus` um eine deklarative Asset-Schicht erweitern
- Python als Orchestrator einsetzen
- zunaechst auf Manifeste und Staging setzen
- spaeter optionale Bundle- und Plattformpipelines aufbauen

Fuer Bilder wie PNG gilt:

- optimierte PNGs bleiben problemlos nutzbar
- verpackte oder transformierte Assets brauchen passende Runtime-Unterstuetzung

Das Thema ist also nicht "geht das mit Python?", sondern eher:

- welches Abstraktionsniveau `exodus` dafuer einfuehren soll
- und wie viel Runtime-Unterstuetzung spaeter fuer Bundle-/Memory-Assets noetig ist
