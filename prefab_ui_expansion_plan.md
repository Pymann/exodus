# Plan: Prefab-System UI-Expansion

## Ziel

UI-Widgets als wiederverwendbare Prefabs definieren statt jedes Frame
imperativ über ui_runtime aufzubauen. Login-Panel von DataCreatures wird
das erste echte Anwendungsbeispiel.

## Design-Entscheidungen (vom User bestätigt)

| Aspekt | Entscheidung |
|--------|-------------|
| ui_runtime | bleibt parallel — neue prefab-UI ist additiv |
| Event-Modell | Callbacks: `on_click: fn_name` |
| Callback-Signatur | `args: [[p, prefab_instance]]` — Instance + getter-methoden |
| Layout | absolute x/y/w/h gegen prefab.design-size, Instance scaling via `is_relative` |
| MVP-Widgets | button, text_input, label, rect/panel |
| Migration | direkt DataCreatures `client_main.aiml` |

## Architektur

### Heutiger Stand
- `prefab_runtime` hat `CHILD_SPRITE` und `CHILD_TEXT`. Children-x/y/w/h
  absolut gegen `prefab.width/height`.
- `Instance.is_relative` skaliert die ganze Instanz (alle Children
  scalen mit) → eignet sich für UI das auf verschiedene Screen-Sizes
  reagieren soll.
- `ui_runtime` hat fertige Widget-Implementierungen (button, text_input,
  Hit-Test, Focus-State, SDF-rounded-rects, Font-Rendering).
- AIML-Compiler kann function-by-name als Callback nutzen (siehe
  `engine.run(win, update, render)`).

### Neue Struktur

```
prefab_runtime.cpp
├── ChildDef { type, x,y,w,h, ... typespezifisch ... , on_click_fn,on_change_fn }
├── Instance { existing fields + widget_states: vector<WidgetState> }
├── WidgetState { union: text{buf, cursor}, button{hot, pressed_now} }
├── render_instance() — dispatched per ChildType:
│   ├── SPRITE/TEXT — wie heute
│   ├── RECT — draw_widget_rect (re-use von ui_runtime, via shared helper)
│   ├── BUTTON — draw_widget_rect + label, schreibt widget_state, prüft hit
│   ├── TEXT_INPUT — draw_widget_rect + text + cursor
│   └── LABEL — push_text (re-use)
└── invoke_callback(inst, child_idx) — schaut ChildDef.on_click_fn,
    schlägt FunctionInfo nach, ruft mit (inst*) auf
```

## Implementation Steps

### Schritt 1: ChildType enum + Parser
**Datei**: `src/sys/prefab_runtime.cpp`

```cpp
enum PrefabChildType {
    CHILD_SPRITE,
    CHILD_TEXT,
    CHILD_RECT,        // NEU
    CHILD_BUTTON,      // NEU
    CHILD_TEXT_INPUT,  // NEU
    CHILD_LABEL,       // NEU (alias auf CHILD_TEXT mit anderer Style-Group)
};

struct PrefabChildDef {
    // ... bestehende Felder ...
    // Style:
    int32_t   bg_color       = 0;
    int32_t   border_color   = 0;
    float     border_width   = 0.0f;
    float     corner_radius  = 0.0f;
    int32_t   label_color    = 0xFFFFFFFF;
    std::string label_text;   // für button: anzuzeigender Text
    bool      is_secret       = false; // password-mode für text_input
    // Callbacks:
    std::string on_click_fn;  // function name (resolved zur Render-Zeit)
    std::string on_change_fn;
};
```

`parse_children_array` erweitern um die neuen Keys.

### Schritt 2: WidgetState per Instance
**Datei**: `src/sys/prefab_runtime.cpp`

```cpp
struct PrefabWidgetState {
    // Button-felder:
    bool hot = false;
    bool pressed_now = false;
    bool clicked_this_frame = false;

    // Text-Input-felder:
    std::string text;
    int cursor_pos = 0;
    bool focused = false;
};

struct AimlPrefabInstance {
    // ... bestehende ...
    std::vector<PrefabWidgetState> widget_states;  // parallel zu def->children
};
```

In `aiml_engine_instantiate` widget_states sizen auf children.size().

### Schritt 3: Drawing-Dispatch
**Datei**: `src/sys/prefab_runtime.cpp::render_instance`

Erweitere den existing dispatch:

```cpp
case CHILD_RECT: {
    // Falls texture: textured quad mit alpha-blending
    // Sonst: draw_widget_rect(x, y, w, h, bg_color, border_color, border_width, corner_radius)
}
case CHILD_BUTTON: {
    auto& ws = inst->widget_states[idx];
    int32_t bg = ws.pressed_now ? ch.active_color
              : ws.hot         ? ch.hover_color
              :                  ch.bg_color;
    draw_widget_rect(ax, ay, aw, ah, bg, ch.border_color, ch.border_width, ch.corner_radius);
    if (!ch.label_text.empty())
        push_text_centered(font, ch.label_text.c_str(), ax, ay, aw, ah, ch.label_color);
}
case CHILD_TEXT_INPUT: {
    auto& ws = inst->widget_states[idx];
    int32_t bg = ws.focused ? ch.active_color : ch.bg_color;
    draw_widget_rect(ax, ay, aw, ah, bg, ch.border_color, ch.border_width, ch.corner_radius);
    const std::string& disp = ch.is_secret ? std::string(ws.text.size(), '*') : ws.text;
    push_text_left(font, disp.c_str(), ax + padding, ay, aw - 2*padding, ch.label_color);
}
case CHILD_LABEL: {
    push_text_centered(font, ch.label_text.c_str(), ax, ay, aw, ah, ch.label_color);
}
```

Helper-Funktionen (`draw_widget_rect`, `push_text_centered`) ggf. aus
ui_runtime extrahieren in einen gemeinsamen Header `gfx_primitives.h`.

### Schritt 4: Input + Callbacks
**Datei**: `src/sys/prefab_runtime.cpp::aiml_engine_update_hover` oder neue Funktion

```cpp
void aiml_prefab_update_input(float mx, float my, int mouse_pressed, int mouse_released) {
    for (auto* inst : g_scene->instances) {
        for (size_t i = 0; i < inst->def->children.size(); i++) {
            auto& ch = inst->def->children[i];
            if (ch.type != CHILD_BUTTON && ch.type != CHILD_TEXT_INPUT) continue;

            // bbox in screen-space:
            float ax = inst_x + ch.x * inst_sx;
            // ... etc, scale-aware ...

            bool hit = (mx >= ax && mx < ax+aw && my >= ay && my < ay+ah);
            auto& ws = inst->widget_states[i];
            ws.hot = hit;

            if (ch.type == CHILD_BUTTON) {
                if (hit && mouse_pressed) ws.pressed_now = true;
                if (mouse_released) {
                    if (ws.pressed_now && hit) {
                        ws.clicked_this_frame = true;
                        if (!ch.on_click_fn.empty())
                            invoke_aiml_callback(ch.on_click_fn, inst);
                    }
                    ws.pressed_now = false;
                }
            } else if (ch.type == CHILD_TEXT_INPUT) {
                if (hit && mouse_pressed) {
                    set_focused_input(inst, i);  // global focus
                }
            }
        }
    }

    // Text-Events an focused_input weiterleiten (Backspace, char-input)
    apply_text_events_to_focused();
}

void invoke_aiml_callback(const std::string& fn_name, AimlPrefabInstance* inst) {
    auto it = g_fn_table.find(fn_name);  // <- ist in fptable.cpp
    if (it == g_fn_table.end()) return;
    using cb_t = void(*)(void*);  // function takes instance ptr
    ((cb_t)it->second)(inst);
}
```

Function-Table: `g_fn_table` ist heute `__aiml_fptable_current[]`. Wir
brauchen Name→Slot-Lookup. Schema_registry hat das vermutlich schon
(check `src/core/schema_registry.h/cpp`).

### Schritt 5: AIML-Compiler Callback-Resolution
**Datei**: `src/core/ast_compiler.cpp::visitTopLevel` (prefab-Decl)

Beim Parsen von `on_click: fn_name`: füge dem Funktion-Symbol-Table
einen Eintrag hinzu, der die Funktion als `prefab_callback` markiert
(damit sie nicht weggemüllt wird). Übergebe den String unmodifiziert
an `aiml_prefab_register_child`.

### Schritt 6: prefab_instance Property-Accessors
**Datei**: `src/core/builtin_registry.cpp`

```cpp
ci.builtinMethods["__getattr__"] = [](ctx, base, call, eval) -> Value* {
    // base = prefab_instance, call.member_name = z.B. "email_in"
    // Returns a small handle-value (i8*) der child-name encodiert
    // Compile-time: erzeuge call zu aiml_prefab_child_handle(inst, name)
};
```

Dann pro WidgetHandle: `.value()` → `aiml_prefab_child_text(handle)`,
`.clicked()` → `aiml_prefab_child_clicked(handle)`.

Einfacher: direkte Methoden auf prefab_instance, name als string:

```aiml
- decl: [email, string, { call: [p.text_value, "email_in"] }]
- if:
    condition: { call: [p.was_clicked, "submit"] }
```

Macht den Compiler-Aufwand viel kleiner — wir registrieren nur 2-3 Methoden auf `prefab_instance`, nicht pro Child-Name.

### Schritt 7: DataCreatures Migration
**Datei**: `sources/client/client_main.aiml`

`render_login` durch Prefab-Definition + Instantiierung ersetzen:

```aiml
- def:
    name: handle_submit
    args: [[p, prefab_instance]]
    body:
      - decl: [email, string, { call: [p.text_value, "email_in"] }]
      - decl: [pass,  string, { call: [p.text_value, "pass_in"]  }]
      - call: [log.info, "submit: ${email}"]

- def:
    name: handle_toggle
    args: [[p, prefab_instance]]
    body:
      - if:
          condition: { eq: [g_mode, 0] }
          then:
            - set: [g_mode, 1]
          else:
            - set: [g_mode, 0]

- prefab:
    name: LoginPanel
    width: 524
    height: 584
    children:
      - { name: frame, type: rect, x: 0, y: 0, width: 524, height: 584,
          texture: "ui/ui_surround.png" }
      - { name: email_in, type: text_input,
          x: 100, y: 200, width: 324, height: 32,
          bg_color: 0x0A1830E6, border_color: 0x66B0E0FF, border_width: 1.5,
          corner_radius: 5.0, label_color: 0x0A1A40FF }
      - { name: pass_in, type: text_input, secret: true,
          x: 100, y: 280, width: 324, height: 32,
          bg_color: 0x0A1830E6, border_color: 0x66B0E0FF, border_width: 1.5,
          corner_radius: 5.0, label_color: 0x0A1A40FF }
      - { name: submit, type: button,
          x: 100, y: 360, width: 324, height: 40,
          bg_color: 0x2A6FB5FF, hover_color: 0x4A8FE0FF, active_color: 0x6AAFFAFF,
          corner_radius: 8.0, label: "Sign In", label_color: 0xFFFFFFFF,
          on_click: handle_submit }
      - { name: toggle, type: button,
          x: 100, y: 410, width: 324, height: 28,
          bg_color: 0x0A1830A0, hover_color: 0x1A3060C0, active_color: 0x2A4080D0,
          corner_radius: 4.0, label: "Register", label_color: 0xFFFFFFFF,
          on_click: handle_toggle }

# In setup:
- decl: [panel, prefab_instance, { call: [engine.instantiate, "LoginPanel"] }]
- call: [panel.set_relative_pos, 0.5, 0.7]   # mittig-unten, scale-aware
```

Das `dc_render` wird damit:

```aiml
- def:
    name: dc_render
    args: []
    body:
      - call: [gl.clear, 0.02, 0.02, 0.04, 1.0]
      - call: [engine.draw_scene]   # zeichnet bg + panel
```

**`render_login` entfällt komplett.**

## Tests

**`tests/test_prefab_ui.aiml`** (~100 LOC):
- Phase A: Button-click triggert callback → globaler counter inkrementiert
- Phase B: Text-Input nimmt key-events, `text_value` returnt eingegebenen Text
- Phase C: Label rendert (visuell, headless skip)
- Phase D: Rect mit texture + bg_color (visuell, headless skip)

`# Requires: display` für visuelle Phasen, Phase A/B kann ohne display laufen indem wir mouse/keyboard programmatisch via test-helpers feuern.

## Risiken & Open Questions

1. **Font-Sharing**: ui_runtime hat `ui.set_default_font`. Prefab nutzt
   `engine.prefab_set_font`. Heute zwei getrennte Fonts. Wir wollen
   das Login-Panel mit der ui.ttf zeichnen → prüfen ob beide Wege
   den gleichen Font teilen können.

2. **SDF-Rendering aus prefab_runtime**: prefab_runtime hat eigenen
   Shader (kein SDF). Wir wollen rounded-rect-Bordern. Optionen:
   - prefab_shader erweitern um SDF-pfad (so wie ui_runtime),
   - oder die UI-Quads über ui_runtime's draw_list emittieren (ui.begin/ui.end um den prefab-draw wrappen).
   → letzteres ist sauberer.

3. **Skalierung**: bei `is_relative` werden Children mit `inst_sx/sy`
   skaliert. UI-Widgets wollen aber meistens KONSTANTE pixel-Größe für
   Text (sonst wird er auf großen Screens riesig). Optional pro Child
   ein `no_scale: true` flag — aber erst in Iteration 2.

4. **Hot-Reload**: prefab-Definitionen sind compilation-time hardcoded.
   Hot-Reload muss new ChildDefs erkennen → siehe fptable/schema_registry
   Hot-Reload-Mechanismus.

## Größe

| Phase | Files | LOC |
|-------|-------|-----|
| 1: ChildType+Parser | prefab_runtime.h/cpp | +60 |
| 2: WidgetState | prefab_runtime.cpp | +50 |
| 3: Drawing | prefab_runtime.cpp (+ gfx_primitives.h?) | +120 |
| 4: Input+Callbacks | prefab_runtime.cpp | +100 |
| 5: Compiler-Side | ast_compiler.cpp (prefab-decl) | +30 |
| 6: Property-API | builtin_registry.cpp | +50 |
| 7: Tests | tests/test_prefab_ui.aiml | +100 |
| 8: Migration | datacreatures client_main.aiml | net ~-50 (entfernt mehr als hinzufügt) |

**Gesamt: ~500 LOC**, ein halber Arbeitstag mit Test+Debug. Native Tests
bleiben grün (alles additiv, ui_runtime unverändert).

## Reihenfolge der Implementierung

1. Schritt 1+2 (Parser + State) ohne Drawing/Input → Build muss grün sein
2. Schritt 3 (Drawing) → minimal test_prefab_ui Phase D (rect+label)
3. Schritt 4 (Input/Callback) → test Phase A (button click)
4. Schritt 6 (Property-API) → test Phase B (text_value)
5. Schritt 7 (Migration) → DataCreatures muss visuell+funktional unverändert sein

Jeder Schritt ist ein einzelner Build/Test-Cycle.
