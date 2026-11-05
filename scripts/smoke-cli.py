#!/usr/bin/env python3
"""Loopback CLI harness: wires two `filejaunt` processes via pipes.

sender stdout --(hello)--> receiver stdin (+ passphrase line)
receiver stdout --(joined)--> sender stdin
Both run with --json --stun none.
"""
import json, subprocess, sys, threading, time, os, hashlib

SEND = sys.argv[1] if len(sys.argv) > 1 else "fixtures/random.bin"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/fjout"
BIN = os.environ.get("FJ", "target/debug/filejaunt")

os.makedirs(OUT, exist_ok=True)

sender = subprocess.Popen(
    [BIN, "send", SEND, "--json", "--stun", "none"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True)
receiver = subprocess.Popen(
    [BIN, "receive", "--out", OUT, "--json", "--yes", "--stun", "none"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True)

def read_line(p, what):
    line = p.stdout.readline()
    if not line:
        return None
    return line.strip()

def send_line(p, line):
    p.stdin.write(line + "\n")
    p.stdin.flush()

# 1) hello from sender -> receiver + passphrase
hello = json.loads(read_line(sender, "hello"))
print("HELLO sid", hello["sid"], "words", len(hello["passphrase"].split("-")), "sender_pid", sender.pid, "receiver_pid", receiver.pid)
send_line(receiver, json.dumps({"type": "hello", "blob1": hello["blob1"]}))
send_line(receiver, hello["passphrase"])

# 2) joined from receiver -> sender (pass p3 blobs if present)
joined = json.loads(read_line(receiver, "joined-wait"))
print("DBG joined type", joined.get("type"), "blob2 len", len(joined.get("blob2","")))
send_line(sender, json.dumps({"type": "joined", "blob2": joined["blob2"]}))
import time as _t; _t.sleep(1.0)
print("DBG sender poll after joined:", sender.poll())

# 3) pump both stdouts continuously (protocol lines routed, rest drained)
done = {"s": False, "r": False}
def pump(src, dst, name):
    try:
        for line in iter(src.stdout.readline, ""):
            try:
                v = json.loads(line)
            except Exception:
                continue
            t = v.get("type")
            if name == "r2s" and t == "blob4":
                send_line(dst, line)
            if t in ("done", "error"):
                done[name[0]] = True
    except Exception:
        pass

t1 = threading.Thread(target=pump, args=(receiver, sender, "r2s"), daemon=True)
t2 = threading.Thread(target=pump, args=(sender, receiver, "s2r"), daemon=True)
t1.start(); t2.start()

scode = sender.wait(timeout=180)
rcode = receiver.wait(timeout=180)
import glob
if scode == 0 and rcode == 0:
    recs = glob.glob(os.path.expanduser("~/.local/share/filejaunt/receipts/*.json"))
    if recs:
        r = max(recs, key=os.path.getmtime)
        v = subprocess.run([BIN, "verify", "--receipt", r], input=hello["passphrase"] + "\n",
                           capture_output=True, text=True)
        print("verify:", v.stdout.strip().splitlines()[0] if v.stdout.strip() else "?", "exit", v.returncode)
        bad = subprocess.run([BIN, "verify", "--receipt", r], input="wrong\n",
                             capture_output=True, text=True)
        print("verify-wrong:", bad.stdout.strip().splitlines()[0] if bad.stdout.strip() else "?", "exit", bad.returncode)
print("sender pid", sender.pid, "exit", scode, "receiver pid", receiver.pid, "exit", rcode)
sys.exit(0 if (scode == 0 and rcode == 0) else 1)
