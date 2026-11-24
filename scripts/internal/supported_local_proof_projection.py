#!/usr/bin/env -S python3 -I
"""Fixed-schema, non-secret supported-local proof projections."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
import zlib

MAX_RAW_BYTES = 4 << 20
MAX_NODE_AGGREGATE_BYTES = 8 << 20
MAX_NODES = 128
MAX_BUNDLE_BYTES = 16 << 20
MAX_TAR_BYTES = 32 << 20
MAX_MEMBER_BYTES = 8 << 20
MAX_WORKSPACE_BYTES = 8 << 20
PROOF_REALIZATION = "supported-local-proof-codex-shim/v1"
PROFILE = "control-plane-normal-shell/v1"
MUTATION = ".codex-proof/normal-shell-proof.txt"
OUTER = frozenset({"runtime-contract-proof.json", "codex-stdout.txt", "codex-stderr.txt",
                   "codex-final-message.txt", "workspace.diff", "workspace.tar.gz"})
WORKSPACE_FILES = frozenset({"README.md", ".codex-proof/codex-proof-result.json",
                             MUTATION, "codex-final-message.txt"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SAFE_TEXT = re.compile(r"[A-Za-z0-9._/-]{1,128}\Z", re.ASCII)
VERSION = re.compile(r"v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z", re.ASCII)
STATES = frozenset({"pending", "running", "terminal", "complete", "failed", "lost"})


class ProjectionError(Exception):
    pass


def require(value: bool) -> None:
    if not value:
        raise ProjectionError


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_input(value: str, maximum: int) -> bytes:
    if value == "-":
        data = sys.stdin.buffer.read(maximum + 1)
    else:
        path = Path(value)
        metadata = os.lstat(path)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and 0 <= metadata.st_size <= maximum)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            require((opened.st_dev, opened.st_ino, opened.st_size) ==
                    (metadata.st_dev, metadata.st_ino, metadata.st_size))
            with os.fdopen(fd, "rb", closefd=False) as source:
                data = source.read(maximum + 1)
            final = os.fstat(fd)
            require((final.st_dev, final.st_ino, final.st_size, final.st_ctime_ns) ==
                    (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_ctime_ns))
        finally:
            os.close(fd)
    require(len(data) <= maximum)
    return data


def clean_absolute(value: object) -> bool:
    return (isinstance(value, str) and value.startswith("/") and not value.startswith("//") and
            value != "/" and os.path.normpath(value) == value)


def open_clean_directory(value: str) -> int:
    require(clean_absolute(value))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in value[1:].split("/"):
            require(part not in ("", ".", ".."))
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except (ProjectionError, OSError):
        os.close(descriptor)
        raise


def open_child_directory(parent: int, name: str) -> int:
    require(name not in ("", ".", "..") and "/" not in name)
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
    require(stat.S_ISDIR(os.fstat(descriptor).st_mode))
    return descriptor


def read_bound_file(parent: int, name: str, maximum: int, expected_size: int | None = None) -> bytes:
    require(name not in ("", ".", "..") and "/" not in name)
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and
            0 <= metadata.st_size <= maximum)
    if expected_size is not None:
        require(metadata.st_size == expected_size)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_ctime_ns, opened.st_mtime_ns) ==
                (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_ctime_ns, metadata.st_mtime_ns))
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(maximum + 1)
        final = os.fstat(descriptor)
        require(stat.S_ISREG(final.st_mode) and final.st_nlink == 1 and
                (final.st_dev, final.st_ino, final.st_size, final.st_ctime_ns, final.st_mtime_ns) ==
                (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_ctime_ns, metadata.st_mtime_ns))
    finally:
        os.close(descriptor)
    require(len(data) == metadata.st_size and len(data) <= maximum)
    return data


def write_bound_output(parent: int, name: str, value: object) -> None:
    data = canonical(value)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_output(path_value: str, value: object) -> None:
    path = Path(path_value)
    require(path.is_absolute() and os.path.normpath(path_value) == path_value)
    parent = path.parent
    metadata = os.lstat(parent)
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode))
    data = canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def json_object(data: bytes) -> dict:
    value = json.loads(data.decode("utf-8", "strict"))
    require(isinstance(value, dict))
    return value


def strict_json_object(data: bytes) -> dict:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        value: dict = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise ProjectionError

    value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=unique_pairs,
                       parse_constant=reject_constant)
    require(isinstance(value, dict))
    return value


def field(value: object, pattern: re.Pattern[str] = SAFE_TEXT) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def nonnegative(value: object, maximum: int) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum else None


def agent_projection(data: bytes) -> dict:
    raw = json_object(data)
    config = raw.get("config", raw.get("Config", {}))
    require(isinstance(config, dict))
    client = config.get("Client", config.get("client", {}))
    server = config.get("Server", config.get("server", {}))
    require(isinstance(client, dict) and isinstance(server, dict))
    return {"schema": "supported-local-nomad-agent-safe-v1",
            "version": field(config.get("Version", raw.get("version", raw.get("Version"))), VERSION),
            "region_present": bool(config.get("Region", config.get("region"))),
            "datacenter_present": bool(config.get("Datacenter", config.get("datacenter"))),
            "node_name_present": bool(config.get("NodeName", config.get("node_name"))),
            "dev_mode": boolean(config.get("DevMode", config.get("dev_mode"))),
            "client_enabled": boolean(client.get("Enabled", client.get("enabled"))),
            "server_enabled": boolean(server.get("Enabled", server.get("enabled")))}


def nodes_projection(data: bytes) -> dict:
    raw = json.loads(data.decode("utf-8", "strict"))
    require(isinstance(raw, list) and len(raw) <= 128 and all(isinstance(item, dict) for item in raw))
    return {"schema": "supported-local-nomad-nodes-safe-v1", "node_count": len(raw),
            "ready_count": sum(item.get("Status") == "ready" for item in raw),
            "eligible_count": sum(item.get("SchedulingEligibility") == "eligible" for item in raw)}


def details_projection(data: bytes) -> dict:
    raw = json.loads(data.decode("utf-8", "strict"))
    require(isinstance(raw, list) and len(raw) <= MAX_NODES and all(isinstance(item, dict) for item in raw))
    positive = 0
    docker_healthy = 0
    for item in raw:
        compute_positive, healthy = detail_facts(item)
        positive += compute_positive
        docker_healthy += healthy
    return {"schema": "supported-local-node-details-safe-v1", "detail_count": len(raw),
            "positive_compute_count": positive, "docker_healthy_count": docker_healthy}


def detail_facts(item: dict) -> tuple[int, int]:
    attrs = item.get("Attributes") or {}
    drivers = item.get("Drivers") or {}
    require(isinstance(attrs, dict) and isinstance(drivers, dict))
    compute_positive = 0
    compute = attrs.get("cpu.totalcompute")
    if isinstance(compute, (int, str)) and not isinstance(compute, bool):
        try:
            compute_positive = int(0 < int(compute) <= 1_000_000_000)
        except ValueError:
            pass
    docker = drivers.get("docker") or {}
    healthy = int(isinstance(docker, dict) and docker.get("Healthy") is True)
    return compute_positive, healthy


def systemd_projection(data: bytes) -> dict:
    values = {}
    for line in data.decode("utf-8", "strict").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "ExecMainStatus"}:
            require(key not in values)
            values[key] = value
    require(values.get("Id") == "nomad.service")
    pid = values.get("MainPID", "")
    exit_status = values.get("ExecMainStatus", "")
    require(pid.isdecimal() and exit_status.isdecimal())
    return {"schema": "supported-local-nomad-service-safe-v1",
            "loaded": values.get("LoadState") == "loaded",
            "active": values.get("ActiveState") == "active",
            "running": values.get("SubState") == "running",
            "enabled": values.get("UnitFileState") == "enabled",
            "main_pid_positive": 0 < int(pid) <= 1_000_000_000,
            "exec_main_status_zero": int(exit_status) == 0}


def docker_projection(data: bytes) -> dict:
    raw = json_object(data)
    plugins = raw.get("Plugins") or {}
    volumes = plugins.get("Volume") if isinstance(plugins, dict) else None
    cpus = nonnegative(raw.get("NCPU"), 1_000_000)
    memory = nonnegative(raw.get("MemTotal"), 1 << 60)
    architecture = raw.get("Architecture")
    driver = raw.get("Driver")
    cgroup = raw.get("CgroupVersion")
    return {"schema": "supported-local-docker-info-safe-v1",
            "server_version": field(raw.get("ServerVersion"), VERSION),
            "architecture": architecture if architecture in ("amd64", "arm64", "x86_64", "aarch64") else None,
            "storage_driver": driver if driver in ("overlay2", "overlay", "btrfs", "zfs", "vfs", "devicemapper") else None,
            "cgroup_version": cgroup if cgroup in ("1", "2") else None,
            "cpu_count": cpus, "memory_bytes": memory,
            "local_volume_capable": "local" in volumes if isinstance(volumes, list) and
            all(isinstance(item, str) for item in volumes) else None}


def leader_projection(data: bytes) -> dict:
    raw = json.loads(data.decode("utf-8", "strict"))
    require(isinstance(raw, str) and len(raw) <= 256)
    return {"schema": "supported-local-nomad-leader-safe-v1", "leader_present": bool(raw)}


def override_projection(data: bytes) -> dict:
    require(data.strip() in (b"true", b"false"))
    return {"schema": "supported-local-compute-override-safe-v1", "override_present": data.strip() == b"true"}


def execution_status_projection(data: bytes) -> dict:
    raw = json_object(data)
    state = raw.get("state", raw.get("State"))
    require(state is None or state in STATES)
    return {"schema": "supported-local-execution-status-safe-v1",
            "state": state, "terminal": boolean(raw.get("terminal", raw.get("Terminal"))),
            "exit_code": nonnegative(raw.get("exit_code", raw.get("ExitCode")), 255)}


def tar_entries(data: bytes, allowed_files: frozenset[str], allowed_dirs: frozenset[str] = frozenset()) -> dict[str, bytes]:
    entries = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            require(name and not name.startswith("/") and "\\" not in name and
                    all(part not in ("", ".", "..") for part in name.split("/")))
            require(name not in seen)
            seen.add(name)
            if name in allowed_dirs:
                require(member.isdir() and member.size == 0)
                continue
            require(name in allowed_files and member.isfile() and
                    member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and
                    0 <= member.size <= MAX_MEMBER_BYTES)
            source = archive.extractfile(member)
            require(source is not None)
            body = source.read(MAX_MEMBER_BYTES + 1)
            require(len(body) == member.size)
            entries[name] = body
        require(not any(byte != 0 for byte in data[archive.offset:]))
    require(set(entries) == allowed_files and seen == allowed_files | allowed_dirs)
    return entries


def bounded_gzip(data: bytes, maximum: int) -> bytes:
    source = zlib.decompressobj(wbits=31)
    result = source.decompress(data, maximum + 1)
    require(len(result) <= maximum and source.eof and not source.unused_data and not source.unconsumed_tail)
    require(not source.flush())
    return result


def proof_report(value: object) -> dict:
    require(isinstance(value, dict) and set(value) == {
        "credential_material_bytes", "credential_material_present", "credential_source",
        "profile", "prompt_sha256", "realization", "status", "workspace_mutation"})
    require(value["credential_material_present"] is True and value["credential_source"] == "workload_vault")
    require(value["profile"] == PROFILE and value["realization"] == PROOF_REALIZATION and value["status"] == "ok")
    require(value["workspace_mutation"] == MUTATION and isinstance(value["prompt_sha256"], str) and
            HEX64.fullmatch(value["prompt_sha256"]) is not None)
    count = value["credential_material_bytes"]
    require(isinstance(count, int) and not isinstance(count, bool) and 1 <= count <= 4096)
    return value


def validate_workspace(data: bytes, report: dict) -> None:
    require(len(data) <= MAX_WORKSPACE_BYTES)
    files = tar_entries(bounded_gzip(data, MAX_WORKSPACE_BYTES), WORKSPACE_FILES, frozenset({".codex-proof"}))
    require(files["README.md"] == b"Execution Substrate CP normal-shell proof workspace\n")
    require(json_object(files[".codex-proof/codex-proof-result.json"]) == report)
    expected_mutation = ("ES_CONTROL_PLANE_NORMAL_SHELL_PROOF\n" +
                         f"profile={PROFILE}\nrealization={PROOF_REALIZATION}\n" +
                         f"prompt_sha256={report['prompt_sha256']}\ncredential_material_present=true\n").encode()
    require(files[MUTATION] == expected_mutation)
    expected_final = ("ES control-plane normal-shell proof completed " +
                      f"prompt_sha256={report['prompt_sha256']} mutation={MUTATION}\n").encode()
    require(files["codex-final-message.txt"] == expected_final)


def validate_diff(data: bytes, report: dict) -> None:
    require(len(data) <= MAX_MEMBER_BYTES)
    text = data.decode("utf-8", "strict")
    require(text.endswith("\n"))
    expected = {
        ".codex-proof/codex-proof-result.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
        MUTATION: "ES_CONTROL_PLANE_NORMAL_SHELL_PROOF\n" +
                  f"profile={PROFILE}\nrealization={PROOF_REALIZATION}\n" +
                  f"prompt_sha256={report['prompt_sha256']}\ncredential_material_present=true\n",
        "codex-final-message.txt": "ES control-plane normal-shell proof completed " +
                                   f"prompt_sha256={report['prompt_sha256']} mutation={MUTATION}\n",
    }
    lines = text.splitlines()
    position = 0
    seen = set()
    while position < len(lines):
        header = lines[position]
        require(header.startswith("diff --git a/"))
        path = header[len("diff --git a/"):].split(" b/", 1)
        require(len(path) == 2 and path[0] == path[1] and path[0] in expected and path[0] not in seen)
        name = path[0]
        seen.add(name)
        body = expected[name].splitlines()
        require(position + 6 + len(body) <= len(lines))
        require(lines[position + 1] in ("new file mode 100644", "new file mode 100600"))
        require(re.fullmatch(r"index 0000000\.\.[0-9a-f]{7,64}", lines[position + 2]) is not None)
        require(lines[position + 3] == "--- /dev/null" and lines[position + 4] == "+++ b/" + name)
        hunk = "@@ -0,0 +1 @@" if len(body) == 1 else f"@@ -0,0 +1,{len(body)} @@"
        require(lines[position + 5] == hunk)
        require(lines[position + 6:position + 6 + len(body)] == ["+" + line for line in body])
        position += 6 + len(body)
    require(seen == set(expected))


def result_projection(data: bytes) -> dict:
    require(0 < len(data) <= MAX_BUNDLE_BYTES)
    members = tar_entries(bounded_gzip(data, MAX_TAR_BYTES), OUTER)
    summary = json_object(members["runtime-contract-proof.json"])
    require(set(summary) == {"status", "profile", "python", "git", "shell", "codex_cli",
                             "credential_source", "credential_secret_path", "credential_secret_field",
                             "credential_material_bytes", "codex", "proof_claim"})
    require(summary["status"] == "ok" and summary["profile"] == PROFILE and
            summary["credential_source"] == "workload_vault" and
            summary["proof_claim"] == "supported-local CP remote normal-shell runtime contract without upstream Codex service")
    require(isinstance(summary["python"], str) and re.fullmatch(r"Python [0-9.]{3,32}", summary["python"]))
    require(isinstance(summary["git"], str) and re.fullmatch(r"git version [0-9.]{3,32}", summary["git"]))
    require(isinstance(summary["shell"], str) and summary["shell"].startswith("GNU bash, version ") and len(summary["shell"]) <= 128)
    require(summary["codex_cli"] == f"codex-proof-shim {PROOF_REALIZATION}")
    require(field(summary["credential_secret_path"]) is not None and field(summary["credential_secret_field"]) is not None)
    report = proof_report(summary["codex"])
    require(summary["credential_material_bytes"] == report["credential_material_bytes"])
    final_message = ("ES control-plane normal-shell proof completed " +
                     f"prompt_sha256={report['prompt_sha256']} mutation={MUTATION}\n").encode()
    require(members["codex-final-message.txt"] == final_message)
    stdout = members["codex-stdout.txt"].decode("utf-8", "strict").splitlines()
    require(len(stdout) == 3 and stdout[0] == "CODEX-PROOF-SHIM-START" and
            json.loads(stdout[1]) == report and stdout[2] == final_message.decode().strip())
    require(members["codex-stderr.txt"] == (
        "codex-proof-shim: credential material acquired from workload_vault\n"
        f"codex-proof-shim: workspace mutated at {MUTATION}\n").encode())
    validate_workspace(members["workspace.tar.gz"], report)
    validate_diff(members["workspace.diff"], report)
    return {"schema": "supported-local-normal-shell-result-evidence-v1",
            "bundle_sha256": sha(data), "bundle_size": len(data),
            "members": [{"path": name, "size": len(members[name]), "sha256": sha(members[name])}
                        for name in sorted(members)],
            "proof_status": "ok", "realization": PROOF_REALIZATION,
            "workspace_mutation_marker_present": True, "final_message_marker_present": True,
            "credential_material_present": True,
            "credential_material_bytes": report["credential_material_bytes"]}


def captured_result_evidence(proof_root: str, output: str) -> None:
    name = "control-plane-normal-shell-result-evidence.json"
    require(clean_absolute(proof_root) and clean_absolute(output) and
            output == os.path.join(proof_root, name))
    proof = open_clean_directory(proof_root)
    try:
        captured = read_bound_file(proof, "control-plane-normal-shell-summary.json", MAX_RAW_BYTES)
        summary = strict_json_object(captured)
        run_id = summary.get("run_id")
        result_bytes = summary.get("result_bytes")
        require(summary.get("ok") is True and summary.get("terminal") is True and
                type(summary.get("exit_code")) is int and summary["exit_code"] == 0 and
                summary.get("result_available") is True and
                isinstance(run_id, str) and re.fullmatch(r"run-[0-9a-f]{16}", run_id, re.ASCII) is not None and
                type(result_bytes) is int and 0 < result_bytes <= MAX_BUNDLE_BYTES)

        lineage = strict_json_object(read_bound_file(
            proof, "control-plane-normal-shell-nomad-execution-safe.json", MAX_RAW_BYTES))
        require(set(lineage) == {"schema", "run_id", "job_id", "allocation_id",
                                 "job_observed", "allocation_observed"} and
                lineage["schema"] == "supported-local-nomad-execution-safe-v1" and
                lineage["run_id"] == run_id and lineage["job_id"] == "exec-" + run_id and
                isinstance(lineage["allocation_id"], str) and
                re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                             lineage["allocation_id"], re.ASCII) is not None and
                lineage["job_observed"] is True and lineage["allocation_observed"] is True)

        workdir = summary.get("workdir")
        result_path = summary.get("result_path")
        require(clean_absolute(workdir) and
                os.path.dirname(workdir) == os.path.join(proof_root, "workdirs") and
                clean_absolute(result_path) and result_path == os.path.join(workdir, "result.tar.gz"))
        workdirs = open_child_directory(proof, "workdirs")
        try:
            selected = open_child_directory(workdirs, os.path.basename(workdir))
            try:
                require(read_bound_file(selected, "summary.json", MAX_RAW_BYTES) == captured)
                bundle = read_bound_file(selected, "result.tar.gz", MAX_BUNDLE_BYTES, result_bytes)
            finally:
                os.close(selected)
        finally:
            os.close(workdirs)
        write_bound_output(proof, name, result_projection(bundle))
    finally:
        os.close(proof)


NOMAD_TOKEN_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n?\Z", re.ASCII)


def nomad_token_header() -> dict:
    """The X-Nomad-Token header from NOMAD_TOKEN_FILE (the read-only observer
    token), or no header when it is unset. The file must be a regular file,
    not a symbolic link, holding one canonical token."""
    path = os.environ.get("NOMAD_TOKEN_FILE", "")
    if not path:
        return {}
    require(path.startswith("/"))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        payload = os.read(descriptor, 64)
    finally:
        os.close(descriptor)
    text = payload.decode("ascii")
    require(NOMAD_TOKEN_PATTERN.fullmatch(text) is not None)
    return {"X-Nomad-Token": text.rstrip("\n")}


def fetch_node_details(base_url: str) -> dict:
    require("?" not in base_url and "#" not in base_url)
    parsed = urllib.parse.urlsplit(base_url)
    port = parsed.port
    require(parsed.scheme in ("http", "https") and parsed.hostname == "127.0.0.1" and
            parsed.username is None and parsed.password is None and port is not None and
            1 <= port <= 65535 and parsed.netloc == f"127.0.0.1:{port}" and
            parsed.path in ("", "/") and not parsed.query and not parsed.fragment)
    base = f"{parsed.scheme}://127.0.0.1:{port}"

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, next_url):
            raise ProjectionError

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = nomad_token_header()
    total_bytes = 0

    def load(url: str) -> object:
        nonlocal total_bytes
        with opener.open(urllib.request.Request(url, headers=headers), timeout=10) as response:
            payload = response.read(MAX_RAW_BYTES + 1)
        require(len(payload) <= MAX_RAW_BYTES)
        total_bytes += len(payload)
        require(total_bytes <= MAX_NODE_AGGREGATE_BYTES)
        return json.loads(payload)

    nodes = load(base + "/v1/nodes")
    require(isinstance(nodes, list) and len(nodes) <= MAX_NODES)
    positive = 0
    docker_healthy = 0
    for node in nodes:
        require(isinstance(node, dict))
        node_id = node.get("ID")
        require(isinstance(node_id, str) and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", node_id, re.ASCII) is not None)
        detail = load(base + "/v1/node/" + node_id)
        require(isinstance(detail, dict))
        compute_positive, healthy = detail_facts(detail)
        positive += compute_positive
        docker_healthy += healthy
    return {"schema": "supported-local-node-details-safe-v1", "detail_count": len(nodes),
            "positive_compute_count": positive, "docker_healthy_count": docker_healthy}


ACTIONS = {
    "host-agent": (agent_projection, "nomad-agent-safe.json"),
    "host-nodes": (nodes_projection, "nomad-nodes-safe.json"),
    "host-node-details": (details_projection, "node-details-safe.json"),
    "host-systemd": (systemd_projection, "nomad-service-safe.json"),
    "host-docker": (docker_projection, "docker-info-safe.json"),
    "host-leader": (leader_projection, "nomad-leader-safe.json"),
    "host-compute-override": (override_projection, "nomad-compute-override-safe.json"),
    "execution-status": (execution_status_projection, "status-safe.json"),
    "result": (result_projection, "control-plane-normal-shell-result-evidence.json"),
}


def main(args: list[str]) -> None:
    require(len(args) == 4 and args[1] in set(ACTIONS) | {"fetch-node-details", "captured-result"})
    action, source, output = args[1:]
    if action == "captured-result":
        captured_result_evidence(source, output)
        return
    if action == "fetch-node-details":
        result = fetch_node_details(source)
        expected = "node-details-safe.json"
    else:
        projector, expected = ACTIONS[action]
        require(Path(output).name == expected or action == "execution-status" and Path(output).name.endswith("-status-safe.json"))
        maximum = MAX_BUNDLE_BYTES if action == "result" else MAX_RAW_BYTES
        result = projector(read_input(source, maximum))
    require(Path(output).name == expected or action == "execution-status" and Path(output).name.endswith("-status-safe.json"))
    write_output(output, result)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ProjectionError, OSError, ValueError, TypeError, KeyError, UnicodeDecodeError,
            json.JSONDecodeError, tarfile.TarError, EOFError, zlib.error):
        print("supported-local safe proof projection failed", file=sys.stderr)
        raise SystemExit(1)
