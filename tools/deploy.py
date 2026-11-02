"""deploy.py - upload an ELF to the console over FTP and run it through
elfldr's URI protocol so argv survives.

  python deploy.py <local.elf> <remote-path> [arg1 arg2 ...]

Without args the raw ELF is streamed to :9021 (elfldr loads it, argc==1).
With args the file is uploaded first and elfldr is asked to load
"file:<remote>?args=<comma separated, URL-encoded>".
"""
import socket
import sys
import time
import urllib.parse
from ftplib import FTP

HOST = "192.168.1.20"
PORT = 9021
FTP_PORT = 2120


def upload(local, remote):
    ftp = FTP()
    ftp.connect(HOST, FTP_PORT, timeout=20)
    ftp.login("anonymous", "a@b.c")
    ftp.voidcmd("TYPE I")
    d = remote.rsplit("/", 1)[0]
    try:
        ftp.mkd(d)
    except Exception:
        pass
    with open(local, "rb") as f:
        ftp.storbinary("STOR " + remote, f, blocksize=65536)
    ftp.quit()


def run_raw(local, idle=600.0, out=None):
    data = open(local, "rb").read()
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(data)
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    print(f"sent raw {len(data)} bytes", flush=True)
    return pump(s, idle, out)


def run_uri(remote, args, idle=600.0, out=None):
    q = "?args=" + urllib.parse.quote(",".join(args), safe="")
    uri = f"file:{remote}{q}"
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(uri.encode() + b"\n")
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    print(f"sent uri {uri}", flush=True)
    return pump(s, idle, out)


def pump(s, idle, out):
    f = open(out, "wb") if out else None
    total = 0
    t0 = time.time()
    s.settimeout(idle)
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            total += len(b)
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()
            if f:
                f.write(b)
                f.flush()
    except socket.timeout:
        print(f"\n[deploy] idle {idle:.0f}s", flush=True)
    finally:
        if f:
            f.close()
        s.close()
    print(f"[deploy] {total} bytes in {time.time() - t0:.1f}s", flush=True)
    return total


if __name__ == "__main__":
    elf, remote = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    if not args:
        run_raw(elf)
    else:
        upload(elf, remote)
        run_uri(remote, args)
