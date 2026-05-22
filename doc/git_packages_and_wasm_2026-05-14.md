# exodus — Git Packages & WASM Output (2026-05-14)

Drei zusammengehörende Erweiterungen in `exodus`, die einen
End-to-End-Pfad von Quellcode zu Browser-WASM ermöglichen.

## 1. `output_type: "wasm"`

Bisherige Werte: `executable`, `static_lib`, `shared_lib`.
Neu: `wasm` — emittiert per emcc-Linker eine drei-Teile-Bundle
`{name}.html` + `{name}.js` + `{name}.wasm`.

Im Schema (`models/project.py`):

```python
output_type: Literal["executable", "static_lib", "shared_lib", "wasm"] = (
    "executable"
)
```

In der Build-Pipeline (`tools/build/build.py`):

- `_linked_output_name()` setzt den Output-Suffix auf `.html` bei
  `wasm`-Builds — emcc emittiert die drei Bundle-Teile automatisch.
- `_link()` wählt `emcc` als Linker, falls `linker.name` nicht
  überschrieben ist.
- Optional: `asset_directories: List[Path]` werden als
  `--preload-file <dir>` an emcc weitergegeben (Asset-Packaging).

## 2. `git_packages`: Toolchains und Repos als deklarierte Dependencies

Neues Feld in `ProjectConfig` parallel zu `apt_packages` und
`conan_packages`. Sinnvoll für Toolchains, die nicht über Distro- oder
Conan-Repos verteilt werden — Paradebeispiel: das Emscripten-SDK
(`emsdk`).

### Schema (`models/packages.py`)

```python
class GitPkg(BaseModel):
    name: str
    repo: str
    ref: str = "HEAD"
    setup_commands: List[List[str]] = []
    required: bool = True
    digest: Optional[str] = None     # gefüllt von pkg install (SHA)
```

### Cache-Layout

```
__exodus_cache/
  apt/<name>/<arch>/<version>/payload/...     (bestehend)
  conan/<...>/                                (bestehend)
  git/<name>/<commit-sha>/                    (neu)
  git/<name>/current   →  <commit-sha>        (Symlink, neu)
```

Der `current`-Symlink wird nach jeder erfolgreichen Installation auf den
aktuellsten Digest aktualisiert. Damit kann `exodus.json` einen stabilen
Pfad referenzieren, ohne den SHA hart zu codieren:

```json
"compiler": {
  "name": "__exodus_cache/git/emsdk/current/upstream/emscripten/emcc"
}
```

### Workflow

1. `git ls-remote {repo} {ref}` löst den Ref zu einem Commit-SHA auf
   (vor dem Klonen).
2. `git clone --depth 1 --branch {ref} {repo} <cache>/git/<name>/<sha>/`
3. Für jede Argv-Liste in `setup_commands`: `subprocess.run(cmd, cwd=<sha-dir>)`.
4. Der resolved SHA wird als `digest` in `exodus.json` zurückgeschrieben.
5. `<sha>` → `current` Symlink wird angelegt/aktualisiert.

### CLI

`exodus pkg install` und `exodus pkg install <name>` verarbeiten ab
sofort beide Pfade. apt-Pakete laufen zuerst (inkl. Symlink-Fix), dann
git-Pakete.

## 3. `_expand_cache` für Compiler / Linker / Env

Bisher wurde die Cache-Variable `__exodus_cache` nur in `search_paths`,
`library_paths`, `linker.flags` und `asset_directories` aufgelöst.

Neu zusätzlich in:

- `compiler.name`
- `linker.name`
- alle `env.*`-Werte (z.B. `EM_CONFIG`)

Damit kann eine Toolchain im Cache deklarativ referenziert werden, ohne
absolute Pfade in exodus.json zu schreiben.

## Beispiel — minimales WASM-Setup

`spike/exodus.json`:

```json
{
    "$schema": "exodus.project.config-1.0",
    "name": "hello_wasm",
    "version": "0.1.0",
    "git_packages": [{
        "name": "emsdk",
        "repo": "https://github.com/emscripten-core/emsdk.git",
        "ref": "main",
        "setup_commands": [
            ["./emsdk", "install", "3.1.74"],
            ["./emsdk", "activate", "3.1.74"]
        ]
    }],
    "output_type": "wasm",
    "sources": ["hello.cpp"],
    "compiler": {
        "name": "__exodus_cache/git/emsdk/current/upstream/emscripten/emcc"
    },
    "linker": {
        "name": "__exodus_cache/git/emsdk/current/upstream/emscripten/emcc"
    },
    "env": {
        "EM_CONFIG": "__exodus_cache/git/emsdk/current/.emscripten"
    }
}
```

Ablauf:

```bash
source ../../exvenv/bin/activate     # setzt EXODUS_CACHE
exodus pkg install                   # klont emsdk + installiert SDK 3.1.74
exodus build                         # → out/hello_wasm/hello_wasm.{html,js,wasm}
```

## Validiert mit

Smoke-Test unter `datacreatures/spike/`:

- `hello.cpp` mit `printf("hello from wasm")`
- Build: 5.4 KB `.wasm`, 54 KB `.js`, 22 KB `.html`
- HTTP-Server: `python3 -m http.server` ausreichend; eigener
  AIML-HTTP-Server steht als nächster Schritt aus.
