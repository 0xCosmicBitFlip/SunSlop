"""Byte splice and the TCP reset Moonlight needs to drop an address."""
import socket
import threading

def _read_http_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        got = sock.recv(4096)
        if not got:
            break
        data += got
        if len(data) > 1 << 20:
            break
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        return data, b""
    return head, rest


def reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct_linger())
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def struct_linger():
    import struct
    return struct.pack("ii", 1, 0)


def splice(left, right, touch):
    stop = threading.Event()

    def pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                touch()
                dst.sendall(data)
        except OSError:
            pass
        finally:
            stop.set()
            for s, how in ((src, socket.SHUT_RD), (dst, socket.SHUT_WR)):
                try:
                    s.shutdown(how)
                except OSError:
                    pass

    a = threading.Thread(target=pump, args=(left, right), daemon=True)
    b = threading.Thread(target=pump, args=(right, left), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()

