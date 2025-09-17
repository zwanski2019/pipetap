import socket
import struct


class PipeTap:
    """
        Class for managing a socket connection to a pipe server.

        :ivar _sock: Internal socket object used for communication with the server.
        :type _sock: socket.socket or None

    """

    def __init__(self):
        self._sock = None

    def _send_pipe_name(self, pipe: str):
        if self._sock is None:
            raise RuntimeError("Not connected")

        name = pipe.encode("utf-8")

        if not (name.endswith(b"\n") or name.endswith(b"\x00")):
            name += b"\n"

        self._sock.sendall(name)

    def _recv_exact(self, n: int) -> bytes:
        chunks = []
        total = 0

        while total < n:
            chunk = self._sock.recv(min(65536, n - total))
            if not chunk:
                raise ConnectionError("Server closed connection while receiving.")

            chunks.append(chunk)
            total += len(chunk)

        return b"".join(chunks)

    def connect(self, pipe: str, host: str, port: int = 61337) -> None:
        """
            Connect to a named pipe server.

            :param pipe:
            :param host:
            :param port:

            :return:
        """
        if self._sock is not None:
            self.close()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(20.0)
        self._sock.connect((host, port))

        self._send_pipe_name(pipe)

    def send(self, data: bytes):
        """
            Send data to a named pipe.

            :param data:
            :return:
        """

        header = struct.pack("!I", len(data))
        self._sock.sendall(header)

        if data:
            self._sock.sendall(data)

    def recv(self):
        """
            Receive data from a named pipe.

            :return:
        """

        header = self._recv_exact(4)
        (length,) = struct.unpack("!I", header)

        if length == 0:
            return b""

        return self._recv_exact(length)

    def close(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
