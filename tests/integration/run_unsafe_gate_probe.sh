#!/usr/bin/env bash
# Real-gdb premises for the unsafe-command gate (audit 2026-10-07).
#
# The gate's matcher is built on how gdb actually resolves commands; this
# probe keeps those premises true against real gdb in the CI matrix
# (ubuntu-22.04 = gdb 12.1, ubuntu-24.04 = gdb 15.x; locally WSL2 = 17.2).
# If gdb ever changes one of these resolutions, the gate must be revisited.
#
# Premises:
#   1. unambiguous prefixes EXECUTE the unsafe command ("she", "py", "so")
#      — so the gate must match abbreviations, not just full words
#   2. the single-letter commands s/r/p/d resolve to step/run/print/delete
#      — so the gate may exempt them without opening a hole
#   3. multi-command strings via newlines execute every line
#      — so the gate must check per line
set -euo pipefail

fail=0
expect_out() { # expect_out <description> <gdb-command> <expected-substring>
    local desc="$1" cmd="$2" want="$3" got
    got="$(gdb -q -nx -batch -ex "$cmd" 2>&1 || true)"
    if [[ "$got" == *"$want"* ]]; then
        echo "ok   $desc"
    else
        echo "FAIL $desc: gdb -ex '$cmd' -> $(echo "$got" | head -1)"
        fail=1
    fi
}

echo "== premise 1: unsafe abbreviations resolve =="
expect_out "'she' executes shell"        'she echo GATE_PROBE_SHELL' 'GATE_PROBE_SHELL'
expect_out "'py' executes python"        'py print(42042)'           '42042'
expect_out "'sou' reaches source"        'sou /tmp/gate-probe-missing' 'No such file or directory'

echo "== premise 2: single-letter canonical commands stay safe =="
# step: complains the program is not running (it resolved to step, NOT shell)
expect_out "'s' resolves to step"        's'   'not being run'
# run: asks for an executable (it resolved to run, NOT restore)
expect_out "'r' resolves to run"         'r'   'No executable file specified'
# print: complains about an empty expression (NOT python)
expect_out "'p' resolves to print"       'p'   'history is empty'
# delete: silently deletes nothing (NOT define/dump)
expect_out "'d' resolves to delete"      'd'   ''

echo "== premise 3: newline-separated commands all run =="
# via gdb.execute exactly like the plugin's eval path (plain -ex swallows
# embedded newlines, which would hide the injection surface)
expect_out "2nd line executes" \
    "python gdb.execute('print 42\nshe echo GATE_PROBE_2ND')" \
    'GATE_PROBE_2ND'

echo "== premise 4: 2026-10-08 gate additions resolve as assumed =="
# append: unambiguous prefix "app" must reach the append command (its
# subcommand listing proves resolution), never something innocent
expect_out "'app' resolves to append"      'app'   'append'
# the two add-auto-load* commands: "add-auto" is AMBIGUOUS between them
# (gdb rejects it), so each full root is its own surface
expect_out "add-auto-load-safe-path exists" \
    'add-auto-load-safe-path' 'argument required'
expect_out "add-auto-load-scripts-directory exists" \
    'add-auto-load-scripts-directory' 'argument required'
# document: "doc" must resolve to document (its usage error proves it)
expect_out "'doc' resolves to document"    'doc'   'Argument required'
# the two set-subcommand surfaces exist under exactly these names
expect_out "set auto-load python-scripts exists" \
    'show auto-load python-scripts' 'Auto-loading of'
expect_out "set startup-with-shell exists" \
    'show startup-with-shell' 'subprocesses'
# prefix-space sanity for the safe exemptions: attach is never append
expect_out "'att' resolves to attach"      'att 999999999' 'ptrace'
# apropos shares "app" prefix space but is a distinct full command
expect_out "'apropos' lists append"        'apropos ^append$' 'append'

if [ "$fail" -ne 0 ]; then
    echo "UNSAFE GATE PREMISES BROKEN"
    exit 1
fi
echo "UNSAFE GATE PREMISES OK"
