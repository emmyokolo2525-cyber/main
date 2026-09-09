import os
import shutil
import stat
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptedWorkspace:
    """
    Provides a temporary workspace where all files are encrypted at rest.
    Exposes an ephemeral localhost HTTP server to allow external tools (like ffmpeg)
    to stream decrypted content in and out without touching the disk in plaintext.
    """

    def __init__(self):
        # Use bytearray to allow true key zeroization
        self.key = bytearray(os.urandom(32))
        self.tmp_dir = tempfile.mkdtemp(prefix="harpocrates-workspace-")
        # Restrictive permissions (0o700)
        os.chmod(self.tmp_dir, stat.S_IRWXU)
        self.path = Path(self.tmp_dir)
        self.allowed_files: set[str] = set()

        self.server: HTTPServer | None = None
        self.server_thread: threading.Thread | None = None
        self.port: int = 0

    def __enter__(self):
        handler_class = self._make_handler()
        self.server = HTTPServer(("127.0.0.1", 0), handler_class)
        self.port = self.server.server_port
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join(timeout=2)

        # Crash cleanup / explicit deletion
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

        # Key zeroization
        if self.key is not None:
            for i in range(len(self.key)):
                self.key[i] = 0
            self.key = None

    def get_url(self, filename: str) -> str:
        """Get an HTTP URL to read from or write to the given filename."""
        self.allowed_files.add(filename)
        return f"http://127.0.0.1:{self.port}/{filename}"

    def write_encrypted(self, filename: str, stream: BinaryIO, size: int | None = None) -> None:
        """Read plaintext from stream and write it encrypted to the workspace."""
        self.allowed_files.add(filename)
        filepath = self.path / filename
        self._encrypt_stream(stream, filepath, size=size)

    def read_decrypted(self, filename: str) -> bytes:
        """Read the entire decrypted file into memory."""
        filepath = self.path / filename
        if not filepath.exists():
            raise FileNotFoundError(f"File {filename} not found in workspace")
        
        import io
        buf = io.BytesIO()
        self._decrypt_stream(filepath, buf)
        return buf.getvalue()

    def sha256(self, filename: str) -> str:
        """Compute SHA-256 hash of the decrypted file."""
        import hashlib
        filepath = self.path / filename
        if not filepath.exists():
            raise FileNotFoundError(f"File {filename} not found in workspace")
            
        class HashStream:
            def __init__(self):
                self.hasher = hashlib.sha256()
            def write(self, b):
                self.hasher.update(b)
                
        h = HashStream()
        self._decrypt_stream(filepath, h)
        return h.hasher.hexdigest()

    def _encrypt_stream(self, src_stream: BinaryIO, dest_path: Path, size: int | None = None) -> None:
        if self.key is None:
            raise RuntimeError("Workspace is closed")
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(bytes(self.key)), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        with open(dest_path, "wb") as f:
            f.write(nonce)
            bytes_read = 0
            while True:
                chunk_size = 65536
                if size is not None:
                    chunk_size = min(chunk_size, size - bytes_read)
                    if chunk_size <= 0:
                        break
                chunk = src_stream.read(chunk_size)
                if not chunk:
                    break
                f.write(encryptor.update(chunk))
                bytes_read += len(chunk)
            f.write(encryptor.finalize())

    def _decrypt_stream(self, src_path: Path, dest_stream: BinaryIO) -> None:
        if self.key is None:
            raise RuntimeError("Workspace is closed")
        with open(src_path, "rb") as f:
            nonce = f.read(16)
            cipher = Cipher(algorithms.AES(bytes(self.key)), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                dest_stream.write(decryptor.update(chunk))
            dest_stream.write(decryptor.finalize())

    def _make_handler(self):
        workspace = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress HTTP server logging

            def do_GET(self):
                filename = self.path.strip("/")
                if filename not in workspace.allowed_files:
                    self.send_response(404)
                    self.end_headers()
                    return
                filepath = workspace.path / filename
                if not filepath.exists():
                    self.send_response(404)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()

                try:
                    workspace._decrypt_stream(filepath, self.wfile)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

            def do_PUT(self):
                filename = self.path.strip("/")
                workspace.allowed_files.add(filename)
                filepath = workspace.path / filename

                content_length = self.headers.get("Content-Length")
                size = int(content_length) if content_length is not None else None

                try:
                    workspace._encrypt_stream(self.rfile, filepath, size=size)
                    self.send_response(201)
                    self.end_headers()
                except Exception:
                    self.send_response(500)
                    self.end_headers()

        return Handler
