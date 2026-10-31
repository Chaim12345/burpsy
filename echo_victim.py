import socket, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 18101)); srv.listen(8)
def handle(c):
    try:
        data = b""
        c.settimeout(5)
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk: break
            data += chunk
        headers, _, rest = data.partition(b"\r\n\r\n")
        cl = 0
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":",1)[1].strip())
        while len(rest) < cl:
            chunk = c.recv(4096)
            if not chunk: break
            rest += chunk
        full = headers + b"\r\n\r\n" + rest
        body = b"ECHO-OF-REQUEST:\n" + full.replace(b"\r\n", b"\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
