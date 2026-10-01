import http.server
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest


binary = Path(sys.argv[1]).resolve()
binary_contents = binary.read_bytes()
operating_system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}[
    platform.system()
]
architecture = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}[platform.machine().lower()]
extension = ".exe" if operating_system == "windows" else ""
asset = os.environ.get("CLI_ASSET", f"ve-{operating_system}-{architecture}{extension}")


class DownloadHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.path == f"/downloads/{asset}":
            self.send_response(302)
            self.send_header("Location", f"/release/{asset}")
            self.end_headers()
            return
        if self.path != f"/release/{asset}" or self.server.mode == "missing":
            self.send_error(404)
            return
        content = b"<html>Not a binary</html>" if self.server.mode == "invalid" else binary_contents
        self.send_response(200)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        try:
            self.wfile.write(content[:128] if self.server.mode == "truncated" else content)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="voe update test ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.executable = self.root / f"ve{extension}"
        shutil.copy2(binary, self.executable)
        self.env_file = self.root / ".env"
        self.env_file.write_text("KEEP_THIS=value\n")
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DownloadHandler)
        self.server.requests = []
        self.server.mode = "ok"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.environment = dict(os.environ)
        self.environment["VOE_BASE_URL"] = f"http://127.0.0.1:{self.server.server_port}/"

    def update(self):
        return subprocess.run(
            [str(self.executable), "update"],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_update_replaces_the_running_executable(self):
        original_inode = self.executable.stat().st_ino
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Updated ve.", result.stdout)
        self.assertEqual(self.server.requests, [f"/downloads/{asset}", f"/release/{asset}"])
        self.assertEqual(self.executable.read_bytes(), binary_contents)
        self.assertNotEqual(self.executable.stat().st_ino, original_inode)
        self.assertEqual(self.env_file.read_text(), "KEEP_THIS=value\n")
        subprocess.run([str(self.executable), "--help"], check=True, stdout=subprocess.DEVNULL)

    def test_failed_download_preserves_the_executable(self):
        for mode in ["missing", "invalid", "truncated"]:
            with self.subTest(mode=mode):
                self.server.mode = mode
                original_inode = self.executable.stat().st_ino
                result = self.update()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Updated ve.", result.stdout)
                self.assertEqual(self.executable.read_bytes(), binary_contents)
                self.assertEqual(self.executable.stat().st_ino, original_inode)
                self.assertEqual(self.env_file.read_text(), "KEEP_THIS=value\n")


unittest.main(argv=[sys.argv[0]])
