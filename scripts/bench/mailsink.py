#!/usr/bin/env python3
"""Test mail sink for the password-reset bench: an SMTP receiver plus a per-recipient HTTP inbox.

usage: mailsink.py SMTP_PORT HTTP_PORT
  GET /inbox?to=<address>  -> JSON {"messages": [{"received": epoch, "subject": s, "body": decoded text}]}
  GET /health              -> ok
Loopback only. Messages are kept in memory; the MIME parts are decoded (quoted-printable, base64)
so the inbox shows what a mail client would show.
"""
import email, email.policy, json, socketserver, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SMTP_PORT, HTTP_PORT = int(sys.argv[1]), int(sys.argv[2])
BOX, LK = {}, threading.Lock()


def decode(raw):
    m = email.message_from_bytes(raw, policy=email.policy.default)
    parts = []
    for p in m.walk():
        if p.get_content_maintype() == 'text':
            try:
                parts.append(p.get_content())
            except Exception:
                parts.append(p.get_payload(decode=True).decode('utf-8', 'replace'))
    return str(m.get('subject', '')), '\n'.join(parts)


class SMTP(socketserver.StreamRequestHandler):
    def w(self, s):
        self.wfile.write((s + '\r\n').encode()); self.wfile.flush()

    def handle(self):
        self.w('220 mailsink ready')
        rcpts = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode('utf-8', 'replace').strip()
            up = cmd.upper()
            if up.startswith('EHLO'):
                self.w('250-mailsink'); self.w('250 8BITMIME')
            elif up.startswith('HELO'):
                self.w('250 mailsink')
            elif up.startswith('MAIL FROM'):
                rcpts = []; self.w('250 ok')
            elif up.startswith('RCPT TO'):
                a = cmd.split(':', 1)[1].strip().strip('<>').split('>')[0].lower()
                rcpts.append(a); self.w('250 ok')
            elif up == 'DATA':
                self.w('354 end with .')
                buf = []
                while True:
                    l = self.rfile.readline()
                    if not l or l in (b'.\r\n', b'.\n'):
                        break
                    buf.append(l[1:] if l.startswith(b'..') else l)
                subj, body = decode(b''.join(buf))
                with LK:
                    for r in rcpts:
                        BOX.setdefault(r, []).append({'received': time.time(), 'subject': subj, 'body': body})
                self.w('250 queued')
            elif up.startswith('QUIT'):
                self.w('221 bye'); return
            elif up.startswith('RSET'):
                rcpts = []; self.w('250 ok')
            else:
                self.w('250 ok')


class HTTP(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == '/health':
            body = b'ok'
        elif u.path == '/inbox':
            to = (urllib.parse.parse_qs(u.query).get('to') or [''])[0].lower()
            with LK:
                body = json.dumps({'messages': list(BOX.get(to, []))[-50:]}).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)


class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


threading.Thread(target=TS(('127.0.0.1', SMTP_PORT), SMTP).serve_forever, daemon=True).start()
ThreadingHTTPServer(('127.0.0.1', HTTP_PORT), HTTP).serve_forever()
