"""Starts a tracker, N seeders and one downloader, then times one download.

Each Cluster is one fresh run. Ablation switches are passed as environment
variables (see common/ablation.hpp) to every process.
"""
import os, resource, shutil, signal, socket, subprocess, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get("TORRENT_BUILD", os.path.join(ROOT, "build-abl"))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cpu_seconds(pids):
    """Total user+system CPU of live processes, from ps (10 ms resolution)."""
    out = subprocess.run(["ps", "-o", "time=", "-p", ",".join(map(str, pids))],
                         capture_output=True, text=True).stdout.split()
    total = 0.0
    for text in out:
        minutes, seconds = text.split(":")
        total += int(minutes) * 60 + float(seconds)
    return total


def loopback_bytes():
    """Bytes sent on lo0 so far (every loopback byte is sent once)."""
    out = subprocess.run(["netstat", "-ib", "-I", "lo0"], capture_output=True, text=True).stdout.splitlines()
    for line in out[1:]:
        f = line.split()
        if f[2].startswith("<Link"):
            return int(f[8])
    return 0


class Client:
    """One client process driven through its prompt."""

    def __init__(self, tracker_conf, env):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [os.path.join(BUILD, "client"), f"127.0.0.1:{self.port}", tracker_conf],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        self.text = ""
        threading.Thread(target=self._read, daemon=True).start()
        for _ in range(400):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("client did not start")

    def _read(self):
        for chunk in iter(lambda: self.proc.stdout.read1(4096), b""):
            self.text += chunk.decode(errors="replace")

    def command(self, line, expect, timeout=60):
        self.text = ""
        self.proc.stdin.write((line + "\n").encode())
        self.proc.stdin.flush()
        end = time.time() + timeout
        while expect not in self.text:
            if time.time() > end:
                raise RuntimeError(f"command failed: {line}\n{self.text}")
            time.sleep(0.005)


class Cluster:
    def __init__(self, env_overrides, seeders, size_bytes, source_file):
        self.env = dict(os.environ, **{k: str(v) for k, v in env_overrides.items()})
        self.dir = tempfile.mkdtemp(prefix="abl-")
        self.source = source_file
        self.size = size_bytes
        self.name = os.path.basename(source_file)
        self.clients = []
        port = free_port()
        subprocess.run([os.path.join(BUILD, "torrent_keygen"), f"127.0.0.1:{port}",
                        f"{self.dir}/keys", f"{self.dir}/client.conf"], check=True,
                       capture_output=True, env=self.env)
        self.tracker = subprocess.Popen([os.path.join(BUILD, "tracker"), f"127.0.0.1:{port}", f"{self.dir}/keys"],
                                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, env=self.env)
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        self.conf = f"{self.dir}/client.conf"
        self.owner = self._client("owner")
        self.owner.command("create group g", "OK group created")
        self.owner.command(f'upload file g "{source_file}"', "OK file shared", 120)
        self.seeders = 1
        for i in range(1, seeders):
            self._add_seeder(f"seeder{i}")

    def _client(self, user):
        c = Client(self.conf, self.env)
        c.command(f"create user {user} pw", "OK user created")
        c.command(f"login {user} pw", "OK logged in")
        self.clients.append(c)
        return c

    def _join(self, c, user):
        c.command("join group g", "OK join requested")
        self.owner.command(f"accept request g {user}", "OK request accepted")

    def _download(self, c, dest, timeout=300):
        c.command(f'download file g {self.name} "{dest}"', "OK download started")
        end = time.time() + timeout
        while not os.path.exists(dest):
            if time.time() > end:
                return False
            time.sleep(0.002)
        return True

    def _add_seeder(self, user):
        c = self._client(user)
        self._join(c, user)
        if not self._download(c, f"{self.dir}/{user}.bin"):
            raise RuntimeError("seeder preparation failed")
        self.seeders += 1

    def measure(self, timeout=300):
        """One timed download by a fresh member. Returns a dict of metrics."""
        c = self._client("leech")
        self._join(c, "leech")
        dest = f"{self.dir}/leech.bin"
        pids = [x.proc.pid for x in self.clients]
        cpu0, net0, wall0 = cpu_seconds(pids), loopback_bytes(), time.perf_counter()
        ok = self._download(c, dest, timeout)
        wall = time.perf_counter() - wall0
        net1 = loopback_bytes()
        cpu1 = cpu_seconds(pids)
        intact = ok and os.path.getsize(dest) == self.size and subprocess.run(
            ["cmp", "-s", dest, self.source]).returncode == 0
        return {"seconds": wall, "mb_per_s": self.size / 1e6 / wall if ok else 0,
                "cpu_seconds": cpu1 - cpu0, "wire_mb": (net1 - net0) / 1e6,
                "completed": int(ok), "intact": int(bool(intact))}

    def close(self):
        for c in self.clients:
            c.proc.kill()
        self.tracker.kill()
        for p in [c.proc for c in self.clients] + [self.tracker]:
            p.wait()
        shutil.rmtree(self.dir, ignore_errors=True)
