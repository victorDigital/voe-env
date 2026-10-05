import http.server
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest


binary = Path(sys.argv[1]).resolve()
binary_contents = binary.read_bytes()
current_version = subprocess.check_output([str(binary), "--version"], text=True).strip().split()[-1]
major, minor, patch = map(int, current_version.split("-")[0].split("+")[0].split("."))
newer_version = f"{major}.{minor}.{patch + 1}"
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
            if self.server.mode == "loop":
                location = self.path
            elif self.server.version:
                location = f"/repo/releases/download/cli-v{self.server.version}/{asset}"
            else:
                location = f"/release/{asset}"
            self.send_header("Location", location)
            self.end_headers()
            return
        if self.path.startswith("/repo/releases/download/"):
            self.send_response(302)
            self.send_header("Location", f"/release/{asset}")
            self.end_headers()
            return
        if self.path != f"/release/{asset}" or self.server.mode == "missing":
            self.send_error(404)
            return
        content = b"<html>Not a binary</html>" if self.server.mode == "invalid" else binary_contents
        self.send_response(200)
        if self.server.mode != "unknown-length":
            self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        try:
            if self.server.mode in ["slow", "unknown-length"]:
                chunk_size = max(1, (len(content) + 11) // 12)
                for offset in range(0, len(content), chunk_size):
                    self.wfile.write(content[offset:offset + chunk_size])
                    self.wfile.flush()
                    time.sleep(0.06)
            else:
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
        self.server.version = None
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
        self.server.version = newer_version
        original_inode = self.executable.stat().st_ino
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Updated ve from {current_version} to {newer_version}.", result.stdout)
        self.assertNotIn("Downloading", result.stdout + result.stderr)
        self.assertNotIn("\x1b", result.stdout + result.stderr)
        self.assertEqual(self.server.requests, [
            f"/downloads/{asset}",
            f"/repo/releases/download/cli-v{newer_version}/{asset}",
            f"/release/{asset}",
        ])
        self.assertEqual(self.executable.read_bytes(), binary_contents)
        self.assertNotEqual(self.executable.stat().st_ino, original_inode)
        self.assertEqual(self.env_file.read_text(), "KEEP_THIS=value\n")
        subprocess.run([str(self.executable), "--help"], check=True, stdout=subprocess.DEVNULL)

    def test_current_release_skips_download_and_replacement(self):
        self.server.version = current_version
        self.server.mode = "invalid"
        original_inode = self.executable.stat().st_ino
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"ve {current_version} is already up to date.", result.stdout)
        self.assertNotIn("Updated ve", result.stdout)
        self.assertEqual(self.server.requests, [f"/downloads/{asset}"])
        self.assertEqual(self.executable.stat().st_ino, original_inode)
        self.assertEqual(self.executable.read_bytes(), binary_contents)
        self.assertEqual(self.env_file.read_text(), "KEEP_THIS=value\n")

    def test_older_release_does_not_downgrade(self):
        self.server.version = "0.0.0"
        original_inode = self.executable.stat().st_ino
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("newer than the latest release (0.0.0)", result.stdout)
        self.assertNotIn("Updated ve", result.stdout)
        self.assertEqual(self.server.requests, [f"/downloads/{asset}"])
        self.assertEqual(self.executable.stat().st_ino, original_inode)
        self.assertEqual(self.executable.read_bytes(), binary_contents)

    def test_identical_custom_download_preserves_the_executable(self):
        original_inode = self.executable.stat().st_ino
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already up to date", result.stdout)
        self.assertNotIn("Updated ve", result.stdout)
        self.assertEqual(self.server.requests, [f"/downloads/{asset}", f"/release/{asset}"])
        self.assertEqual(self.executable.stat().st_ino, original_inode)
        self.assertEqual(self.executable.read_bytes(), binary_contents)

    @unittest.skipIf(os.name == "nt", "PTY verification requires a Unix terminal")
    def test_terminal_progress_with_and_without_content_length(self):
        import pty
        import select

        for mode in ["slow", "unknown-length"]:
            with self.subTest(mode=mode):
                self.server.mode = mode
                original_inode = self.executable.stat().st_ino
                master, slave = pty.openpty()
                process = None
                try:
                    environment = {**self.environment, "TERM": "xterm", "COLUMNS": "100"}
                    process = subprocess.Popen(
                        [str(self.executable), "update"],
                        cwd=self.root,
                        env=environment,
                        stdout=slave,
                        stderr=slave,
                    )
                    output = bytearray()
                    deadline = time.monotonic() + 20
                    while process.poll() is None:
                        if time.monotonic() >= deadline:
                            self.fail(f"Terminal update timed out: {output.decode(errors='replace')}")
                        if select.select([master], [], [], 0.1)[0]:
                            output.extend(os.read(master, 65536))
                    while select.select([master], [], [], 0)[0]:
                        output.extend(os.read(master, 65536))
                finally:
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait()
                    os.close(slave)
                    os.close(master)
                self.assertEqual(process.returncode, 0, output.decode(errors="replace"))
                self.assertIn(b"Downloading", output)
                if mode == "slow":
                    self.assertIn(b"Downloading [", output)
                    self.assertIn(b"%", output)
                else:
                    self.assertNotIn(b"%", output)
                self.assertIn(b"already up to date", output)
                self.assertEqual(self.executable.stat().st_ino, original_inode)
                self.assertEqual(self.executable.read_bytes(), binary_contents)

    def test_failed_download_preserves_the_executable(self):
        for mode in ["missing", "invalid", "truncated", "loop"]:
            with self.subTest(mode=mode):
                self.server.mode = mode
                original_inode = self.executable.stat().st_ino
                result = self.update()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Updated ve", result.stdout)
                self.assertEqual(self.executable.read_bytes(), binary_contents)
                self.assertEqual(self.executable.stat().st_ino, original_inode)
                self.assertEqual(self.env_file.read_text(), "KEEP_THIS=value\n")


unittest.main(argv=[sys.argv[0]])
