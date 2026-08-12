#!/usr/bin/env bash
# test-gdbstub.sh - Validate LLDB <-> elfuse gdbstub interaction
#
# Copyright 2026 elfuse contributors
# Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Starts elfuse with --gdb --gdb-stop-on-entry, drives LLDB in batch mode,
# and validates register reads, memory reads, breakpoints, stepping, and
# watchpoints.
#
# Usage: tests/test-gdbstub.sh [-e ELFUSE] [-v]
#   -e ELFUSE  Path to elfuse binary (default: build/elfuse)
#   -v         Verbose: show LLDB output on failure

set -uo pipefail

ELFUSE="${ELFUSE:-build/elfuse}"
VERBOSE=0

while getopts "e:v" opt; do
    case "$opt" in
        e) ELFUSE="$OPTARG" ;;
        v) VERBOSE=1 ;;
        *)
            echo "Usage: $0 [-e elfuse] [-v]" >&2
            exit 1
            ;;
    esac
done

# Prerequisites
if [ ! -x "$ELFUSE" ]; then
    echo "error: $ELFUSE not found or not executable" >&2
    echo "  Build with: make elfuse" >&2
    exit 1
fi

if ! command -v lldb > /dev/null 2>&1; then
    echo "error: lldb not found in PATH" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDIR="${TESTDIR:-$(cd "$SCRIPT_DIR/.." && pwd)/build}"

# test-hello is a static aarch64 ELF with known addresses:
#   0x400000 _start: mov x0, #1
#   0x400004         adr x1, msg
#   0x400008         mov x2, #6
#   0x40000c         mov x8, #64
#   0x400010         svc #0
#   0x400014         mov x0, #0
#   0x400018         mov x8, #93
#   0x40001c         svc #0
#   0x400020 msg:    "hello\n"
GUEST="$TESTDIR/test-hello"
if [ ! -f "$GUEST" ]; then
    echo "error: $GUEST not found (run make test-hello)" >&2
    exit 1
fi

# Colors
if [ -t 1 ]; then
    GREEN='\033[32m' RED='\033[31m' RESET='\033[0m'
else
    GREEN="" RED="" RESET=""
fi

# Helpers
passes=0
fails=0
elfuse_pid=""
GDB_PORT=""
GDB_STDERR=""

# Find a free TCP port
find_free_port()
{
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
"
}

# Start elfuse with gdb stub and wait for it to be ready
start_elfuse()
{
    local guest="$1"
    shift
    GDB_PORT=$(find_free_port)
    if [ -z "$GDB_STDERR" ]; then
        GDB_STDERR=$(mktemp "${TMPDIR:-/tmp}/elfuse-gdb-stderr.XXXXXX") || return 1
    fi
    : > "$GDB_STDERR" || return 1
    "$ELFUSE" --gdb "$GDB_PORT" --gdb-stop-on-entry "$guest" "$@" > /dev/null 2> "$GDB_STDERR" &
    elfuse_pid=$!

    # Wait for the gdb stub to be listening (up to 5 seconds)
    local tries=0
    while ! grep -q "Waiting for GDB to attach" "$GDB_STDERR" 2> /dev/null; do
        sleep 0.1
        tries=$((tries + 1))
        if [ $tries -ge 50 ]; then
            echo "error: elfuse gdb stub did not start within 5s" >&2
            kill "$elfuse_pid" 2> /dev/null
            return 1
        fi
        # Check if elfuse already exited
        if ! kill -0 "$elfuse_pid" 2> /dev/null; then
            echo "error: elfuse exited prematurely" >&2
            [ "$VERBOSE" -eq 1 ] && cat "$GDB_STDERR" >&2
            return 1
        fi
    done
    return 0
}

stop_elfuse()
{
    if [ -n "$elfuse_pid" ] && kill -0 "$elfuse_pid" 2> /dev/null; then
        kill "$elfuse_pid" 2> /dev/null
        wait "$elfuse_pid" 2> /dev/null || true
    fi
    elfuse_pid=""
    if [ -n "$GDB_STDERR" ]; then
        rm -f "$GDB_STDERR"
        GDB_STDERR=""
    fi
    # Brief pause for TCP port cleanup (SO_REUSEADDR helps but not instant)
    sleep 0.2
}

# Run LLDB in batch mode with the given commands.
# Captures stdout+stderr into $LLDB_OUT.
# Returns LLDB's exit code.
run_lldb()
{
    local timeout_sec="${LLDB_TIMEOUT:-10}"
    LLDB_OUT=$(timeout "$timeout_sec" lldb --batch \
        -o "gdb-remote $GDB_PORT" \
        "$@" 2>&1) || true
}

run_raw_rsp_script()
{
    local timeout_sec="${RAW_RSP_TIMEOUT:-10}"
    RAW_RSP_OUT=$(
        timeout "$timeout_sec" python3 - "$GDB_PORT" 2>&1 << 'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=5)
sock.settimeout(5)

def send_packet(payload: str) -> None:
    data = payload.encode("ascii")
    cksum = sum(data) & 0xFF
    sock.sendall(b"$" + data + b"#" + f"{cksum:02x}".encode("ascii"))

def recv_exact(n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        buf += chunk
    return buf

def recv_packet():
    lead = recv_exact(1)
    ack = ""
    if lead in (b"+", b"-"):
        ack = lead.decode("ascii")
        lead = recv_exact(1)
    if lead != b"$":
        raise RuntimeError(f"unexpected lead byte: {lead!r}")
    body = bytearray()
    while True:
        ch = recv_exact(1)
        if ch == b"#":
            break
        body.extend(ch)
    cksum = recv_exact(2).decode("ascii")
    return ack, body.decode("ascii"), cksum

send_packet("qSupported")
ack1, body1, cksum1 = recv_packet()
print(f"qSupported_ack={ack1 or 'none'}")
print(f"qSupported_body={body1}")
print(f"qSupported_cksum={cksum1}")

send_packet("QStartNoAckMode")
ack2, body2, cksum2 = recv_packet()
print(f"noack_ack={ack2 or 'none'}")
print(f"noack_body={body2}")
print(f"noack_cksum={cksum2}")

send_packet("?")
ack3, body3, cksum3 = recv_packet()
print(f"stop_ack={ack3 or 'none'}")
print(f"stop_body={body3}")
print(f"stop_cksum={cksum3}")

sock.close()
PY
    ) || true
}

report()
{
    local name="$1"
    local ok="$2"
    if [ "$ok" -eq 1 ]; then
        printf "%-50s [ ${GREEN}OK${RESET} ]\n" "$name"
        passes=$((passes + 1))
    else
        printf "%-50s [ ${RED}FAIL${RESET} ]\n" "$name"
        fails=$((fails + 1))
        if [ "$VERBOSE" -eq 1 ]; then
            if [ -n "${LLDB_OUT:-}" ]; then
                echo "$LLDB_OUT" | head -20 | sed 's/^/    /'
            fi
            if [ -n "${RAW_RSP_OUT:-}" ]; then
                echo "$RAW_RSP_OUT" | head -20 | sed 's/^/    /'
            fi
        fi
    fi
}

# Cleanup on exit
cleanup()
{
    stop_elfuse
    if [ -n "$GDB_STDERR" ]; then
        rm -f "$GDB_STDERR"
        GDB_STDERR=""
    fi
}
trap cleanup EXIT

# Test 1: Connect and stop-on-entry
echo "GDB stub tests (LLDB <-> elfuse)"

start_elfuse "$GUEST"
run_lldb \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# PC should be at _start (0x400000)
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400000"; then
    ok=1
fi
report "stop-on-entry: PC at _start (0x400000)" $ok
stop_elfuse

# Test 2: Register read (GPRs)
start_elfuse "$GUEST"
run_lldb \
    -o "register read x0 x1 x2 x8 sp" \
    -o "process kill" \
    -o "quit"
# At entry, registers should be readable (SP should be nonzero)
ok=0
if echo "$LLDB_OUT" | grep -qi "sp.*=.*0x"; then
    ok=1
fi
report "register read: GPRs readable at entry" $ok
stop_elfuse

# Test 3: Memory read at known address
start_elfuse "$GUEST"
run_lldb \
    -o "memory read 0x400020 --count 6 --format c" \
    -o "process kill" \
    -o "quit"
# 0x400020 is msg: "hello\n" -- should contain 'h','e','l','l','o'
ok=0
if echo "$LLDB_OUT" | grep -q "hello"; then
    ok=1
fi
report "memory read: msg at 0x400020 contains 'hello'" $ok
stop_elfuse

# Test 4: Memory read of instructions
start_elfuse "$GUEST"
run_lldb \
    -o "memory read 0x400000 --count 4 --format x" \
    -o "process kill" \
    -o "quit"
# First instruction is mov x0, #1 = 0xd2800020
ok=0
if echo "$LLDB_OUT" | grep -qi "20.*00.*80.*d2\|d2800020"; then
    ok=1
fi
report "memory read: first instruction bytes readable" $ok
stop_elfuse

# Test 5: Single step
start_elfuse "$GUEST"
run_lldb \
    -o "thread step-inst" \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# After stepping one instruction from 0x400000, PC should be 0x400004
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400004"; then
    ok=1
fi
report "single step: PC advances to 0x400004" $ok
stop_elfuse

# Test 6: Multiple steps
start_elfuse "$GUEST"
run_lldb \
    -o "thread step-inst" \
    -o "thread step-inst" \
    -o "thread step-inst" \
    -o "register read pc x0 x1 x2" \
    -o "process kill" \
    -o "quit"
# After 3 steps from 0x400000: at 0x40000c
# x0 should be 1 (stdout), x2 should be 6 (count)
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*40000c"; then
    ok=1
fi
report "multiple steps: PC at 0x40000c after 3 steps" $ok
stop_elfuse

# Test 7: Hardware breakpoint
start_elfuse "$GUEST"
run_lldb \
    -o "breakpoint set --address 0x400014" \
    -o "continue" \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# Should hit breakpoint at 0x400014 (mov x0, #0 -- the exit setup)
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400014"; then
    ok=1
fi
report "hardware breakpoint: stop at 0x400014" $ok
stop_elfuse

# Test 8: Register state after stepping
start_elfuse "$GUEST"
run_lldb \
    -o "thread step-inst" \
    -o "thread step-inst" \
    -o "thread step-inst" \
    -o "register read x0 x1 x2" \
    -o "process kill" \
    -o "quit"
# After 3 steps (past mov x0,#1 / adr x1,msg / mov x2,#6):
# x0=1 (stdout), x2=6 (count), x1 = 0x400020 (msg addr)
ok=0
x0_ok=0
x2_ok=0
echo "$LLDB_OUT" | grep -q "x0.*0x0*1$" && x0_ok=1
echo "$LLDB_OUT" | grep -q "x2.*0x0*6$" && x2_ok=1
[ $x0_ok -eq 1 ] && [ $x2_ok -eq 1 ] && ok=1
report "step + regs: x0=1, x2=6 after 3 steps" $ok
stop_elfuse

# Test 9: Continue to exit
start_elfuse "$GUEST"
run_lldb \
    -o "continue" \
    -o "quit"
# elfuse should exit cleanly (process exits with code 0)
ok=0
if echo "$LLDB_OUT" | grep -qi "exited\|exit.*status.*0\|Process.*exit"; then
    ok=1
fi
# Also accept: elfuse process no longer running
if [ $ok -eq 0 ] && ! kill -0 "$elfuse_pid" 2> /dev/null; then
    ok=1
fi
report "continue to exit: guest runs to completion" $ok
stop_elfuse

# Test 10: Disassemble at entry
start_elfuse "$GUEST"
run_lldb \
    -o "disassemble --start-address 0x400000 --count 5" \
    -o "process kill" \
    -o "quit"
# Should show aarch64 instructions including mov, adr, svc
ok=0
if echo "$LLDB_OUT" | grep -qi "mov\|svc"; then
    ok=1
fi
report "disassemble: decodes aarch64 instructions" $ok
stop_elfuse

# Test 11: Memory write (to writable stack region)
start_elfuse "$GUEST"
# Read SP first, then write 4 bytes below SP (stack is RW)
run_lldb \
    -o "register read sp" \
    -o "script addr = lldb.frame.FindRegister('sp').GetValueAsUnsigned() - 64" \
    -o "script lldb.process.WriteMemory(addr, b'ABCD', lldb.SBError())" \
    -o "script e = lldb.SBError(); data = lldb.process.ReadMemory(addr, 4, e); print('readback:', data)" \
    -o "process kill" \
    -o "quit"
ok=0
if echo "$LLDB_OUT" | grep -q "ABCD\|readback.*ABCD\|b'ABCD'"; then
    ok=1
fi
report "memory write: write and readback on stack" $ok
stop_elfuse

# Test 12: Register write (modify PC)
start_elfuse "$GUEST"
run_lldb \
    -o "register write pc 0x400014" \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# PC should now show 0x400014
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400014"; then
    ok=1
fi
report "register write: set PC to 0x400014" $ok
stop_elfuse

# Test 13: Thread info
start_elfuse "$GUEST"
run_lldb \
    -o "thread list" \
    -o "process kill" \
    -o "quit"
# Should show at least one thread
ok=0
if echo "$LLDB_OUT" | grep -qi "thread.*#\|stop reason"; then
    ok=1
fi
report "thread list: at least one thread visible" $ok
stop_elfuse

# Test 14: Detach (guest continues)
start_elfuse "$GUEST"
run_lldb \
    -o "process detach" \
    -o "quit"
# After detach, elfuse should continue running and exit on its own
sleep 0.5
ok=0
if ! kill -0 "$elfuse_pid" 2> /dev/null; then
    # elfuse exited after detach -- guest ran to completion
    ok=1
fi
report "detach: guest continues and exits after detach" $ok
stop_elfuse

# Test 15: Multiple breakpoints
start_elfuse "$GUEST"
run_lldb \
    -o "breakpoint set --address 0x400004" \
    -o "breakpoint set --address 0x40000c" \
    -o "continue" \
    -o "register read pc" \
    -o "continue" \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# Should hit first bp at 0x400004, then second at 0x40000c
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400004" \
    && echo "$LLDB_OUT" | grep -qi "0x.*40000c"; then
    ok=1
fi
report "multiple breakpoints: hit both in sequence" $ok
stop_elfuse

# Test 16: Breakpoint delete + continue
start_elfuse "$GUEST"
run_lldb \
    -o "breakpoint set --address 0x400004" \
    -o "breakpoint set --address 0x400014" \
    -o "breakpoint delete 1" \
    -o "continue" \
    -o "register read pc" \
    -o "process kill" \
    -o "quit"
# Deleted bp at 0x400004, should only stop at 0x400014
ok=0
if echo "$LLDB_OUT" | grep -qi "0x.*400014"; then
    ok=1
fi
report "breakpoint delete: skip deleted, stop at remaining" $ok
stop_elfuse

# Test 17: QStartNoAckMode transport negotiation
start_elfuse "$GUEST"
run_raw_rsp_script
ok=0
if echo "$RAW_RSP_OUT" | grep -q "qSupported_ack=+" \
    && echo "$RAW_RSP_OUT" | grep -q "qSupported_body=.*QStartNoAckMode+" \
    && echo "$RAW_RSP_OUT" | grep -q "noack_ack=+" \
    && echo "$RAW_RSP_OUT" | grep -q "noack_body=OK" \
    && echo "$RAW_RSP_OUT" | grep -q "stop_ack=none" \
    && echo "$RAW_RSP_OUT" | grep -q "stop_body=T05"; then
    ok=1
fi
report "QStartNoAckMode: final ack then packet-only replies" $ok
stop_elfuse

# Test 18: teardown with a client still attached
#
# gdb_stub_shutdown() runs on the main thread the moment the guest exits, and
# the caller unmaps the guest slab right after it returns. It therefore has to
# wake the listener thread and join it, since a listener still parked in
# poll() is free to accept a packet and let handle_packet read that mapping.
#
# The join needs a wakeup that works: close(2) on a descriptor another thread
# is blocked on does not portably wake it, so without the shutdown pipe the
# join blocks forever and elfuse never exits. That hang is what this pins.
# The use-after-unmap itself is a race and cannot be forced from here, so on
# that axis this is a regression guard rather than a reproduction.
start_elfuse "$GUEST"
# `continue` and nothing else: LLDB stays attached while the guest runs to
# exit, which is the ordering the shutdown path has to survive.
LLDB_TIMEOUT=20 run_lldb -o "continue"
ok=0
# Bounded wait for elfuse itself, so a join that never returns fails here
# instead of hanging the suite.
waited=0
while kill -0 "$elfuse_pid" 2> /dev/null && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
if kill -0 "$elfuse_pid" 2> /dev/null; then
    [ "$VERBOSE" -eq 1 ] && echo "elfuse still alive 10s after guest exit" >&2
else
    wait "$elfuse_pid" 2> /dev/null
    elfuse_rc=$?
    # The guest must have run to completion, and elfuse must report its exit
    # rather than a signal (>= 128) from faulting on the unmapped slab.
    if [ "$elfuse_rc" -lt 128 ] && echo "$LLDB_OUT" | grep -qi "exited with status"; then
        ok=1
    fi
fi
report "teardown with a client attached exits cleanly" $ok
stop_elfuse

# Test 19: teardown while the listener is blocked mid-packet
#
# gdb_stub_shutdown() wakes the listener through shutdown_pipe, but that pipe
# is only read at the two poll() sites. gdb_rsp_recv blocks in read(2) once it
# has consumed a packet fragment without reaching the "#" trailer, and the
# client socket stays open until after pthread_join by design (closing it
# earlier would recycle the descriptor number under the listener). A listener
# parked in that read(2) therefore never reaches poll() again, so the join
# cannot complete and elfuse never exits.
#
# The Linux contract being leaned on is the shutdown(2)/close(2) asymmetry:
# shutdown(fd, SHUT_RDWR) makes a concurrent read(2) on that socket return 0,
# whereas close(2) on a descriptor another thread is already blocked on does
# not portably wake it. The fix calls shutdown(2) before the join and keeps
# close(2) after it.
#
# The regression this pins is a permanent hang, so the lane waits for elfuse
# with a bounded loop rather than blocking on wait(1). test-sleep is the guest
# because test-hello exits within microseconds of the continue packet, leaving
# no window in which the fragment is certain to arrive while the guest runs.
SLEEP_GUEST="$TESTDIR/test-sleep"
if [ ! -f "$SLEEP_GUEST" ]; then
    echo "note: $SLEEP_GUEST not built, skipping mid-packet teardown lane" >&2
else
    start_elfuse "$SLEEP_GUEST"
    # Hold the connection open from a background helper: if the socket closed,
    # read(2) would return 0 on its own and the hang would not reproduce.
    RAW_HOLD_OUT=$(mktemp "${TMPDIR:-/tmp}/elfuse-gdb-hold.XXXXXX")
    python3 - "$GDB_PORT" > "$RAW_HOLD_OUT" 2>&1 << 'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=5)
sock.settimeout(5)

# Give gdb_stub_wait_for_attach time to reach its stopped state before
# resuming it. A "c" that wins the race against the gdb.all_stopped store
# there clears the flag before it is set, and the guest never starts at all;
# elfuse would then hang for a reason that has nothing to do with the teardown
# path under test. The window is the microseconds the main thread needs to
# reacquire gdb.lock after the stop_cond broadcast, so this sleep makes losing
# it vanishingly unlikely without being able to rule it out. build_stop_reply
# ignores gdb.all_stopped, so the reply below cannot serve as that barrier.
time.sleep(0.5)
sock.sendall(b"$?#3f")
reply = sock.recv(200)
if not reply.startswith(b"+$T") and not reply.startswith(b"+$S"):
    print(f"unexpected stop reply: {reply!r}")
    sys.exit(1)
print("stop reply received")

# Resume the guest: it now runs for the length of test-sleep's nanosleep.
sock.sendall(b"$c#63")
if sock.recv(1) != b"+":
    print("continue was not acknowledged")
    sys.exit(1)
print("continue acked")

# A fragment with no "#" trailer. The stub consumes these bytes and blocks in
# read(2) waiting for the rest of the packet, which never arrives.
time.sleep(0.3)
sock.sendall(b"$m0,4")
print("fragment sent")

# Outlive the bounded wait below without closing the socket.
time.sleep(15)
PY
    hold_pid=$!
    ok=0
    # Bounded wait: a join that never returns must fail here, not hang the suite.
    waited=0
    while kill -0 "$elfuse_pid" 2> /dev/null && [ "$waited" -lt 80 ]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    if kill -0 "$elfuse_pid" 2> /dev/null; then
        [ "$VERBOSE" -eq 1 ] &&
            echo "elfuse still alive 8s after a mid-packet shutdown" >&2
    else
        wait "$elfuse_pid" 2> /dev/null
        elfuse_rc=$?
        # Exit status, not a signal (>= 128) from faulting on the unmapped slab.
        [ "$elfuse_rc" -lt 128 ] && ok=1
    fi
    if [ "$VERBOSE" -eq 1 ]; then
        RAW_RSP_OUT=$(cat "$RAW_HOLD_OUT" 2> /dev/null)
    fi
    kill "$hold_pid" 2> /dev/null
    wait "$hold_pid" 2> /dev/null || true
    rm -f "$RAW_HOLD_OUT"
    report "teardown while the listener is mid-packet exits" $ok
    stop_elfuse
fi

# Summary
echo ""
if [ "$fails" -eq 0 ]; then
    printf "  All %d tests passed\n" "$passes"
else
    printf "  Results: %d passed, %d failed\n" "$passes" "$fails"
fi

[ "$fails" -eq 0 ]
