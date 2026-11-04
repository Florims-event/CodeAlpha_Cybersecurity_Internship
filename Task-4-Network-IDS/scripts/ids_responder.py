#!/usr/bin/env python3
"""Simple automatic response for Suricata alerts (Task 4).

Reads Suricata's eve.json alert log. When the port-scan rule (sid 1000002)
fires, the attacker's IP address is blocked with iptables.
Default mode is DRY RUN: it only reports what it WOULD block.
Use --block to really block.  Use --unblock IP to undo a block.
"""
import argparse
import ipaddress
import json
import os
import subprocess
import time
from datetime import datetime

SCAN_SID = 1000002
PROTECTED = {"127.0.0.1", "192.168.100.1", "10.0.0.1", "10.0.0.2"}


def log(message, logfile):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}"
    print(line, flush=True)
    with open(logfile, "a") as handle:
        handle.write(line + "\n")


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def iptables(action, ip):
    flag = "-I" if action == "add" else "-D"
    return subprocess.run(["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"],
                          capture_output=True, text=True, timeout=10)


def follow(path, replay):
    with open(path, "r") as handle:
        if not replay:
            handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--eve", default="logs/eve.json")
    parser.add_argument("--out", default="logs/response.log")
    parser.add_argument("--block", action="store_true", help="really block (default is dry run)")
    parser.add_argument("--replay", action="store_true", help="also read alerts already in the file")
    parser.add_argument("--unblock", metavar="IP", help="remove a block and exit")
    args = parser.parse_args()

    if args.unblock:
        if not valid_ip(args.unblock):
            raise SystemExit("Not a valid IP address")
        result = iptables("del", args.unblock)
        log(f"UNBLOCK {args.unblock} (exit code {result.returncode})", args.out)
        return

    mode = "BLOCK" if args.block else "DRY RUN"
    log(f"Responder started in {mode} mode, watching {args.eve}", args.out)
    blocked = set()
    for line in follow(args.eve, args.replay):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "alert":
            continue
        sid = event["alert"]["signature_id"]
        src = event.get("src_ip", "")
        name = event["alert"]["signature"]
        log(f"ALERT sid={sid} src={src} {name}", args.out)
        if sid != SCAN_SID or not valid_ip(src) or src in PROTECTED or src in blocked:
            continue
        blocked.add(src)
        if args.block:
            result = iptables("add", src)
            log(f"RESPONSE blocked {src} (exit code {result.returncode})", args.out)
        else:
            log(f"RESPONSE would block {src} (dry run)", args.out)


if __name__ == "__main__":
    main()
