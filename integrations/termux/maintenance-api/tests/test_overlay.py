"""Host-only byte reconstruction; Python standard library and Git, no Android SDK."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "b63c00ce197df08df707fe4da2e8d62d3973e5ff"
SOURCE = "15e90b14ec36fe4b107520ea6b237557b170ea6c"
SERVICE = "app/src/main/java/com/termux/app/privateadb/PrivateAdbService.java"
FIXTURE_SHA256 = "fc9b777ab94e89149f0bd5ec5c6135fcc6090b55c495f12ce974c95f84d2a761"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("not a portable relative path")
    parts = value.split("/")
    if any(not part or part in (".", "..") or ":" in part for part in parts):
        raise ValueError("unsafe path component")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError("unsupported path character")
    if PurePosixPath(value).is_absolute():
        raise ValueError("absolute path")
    return Path(*parts)


def checked_file(root, value):
    relative = safe_relative(value)
    root = root.resolve()
    current = root
    for part in relative.parts:
        current = current / part
        is_junction = getattr(current, "is_junction", lambda: False)
        if current.is_symlink() or is_junction():
            raise ValueError("linked artifact path")
    if not current.is_file() or not current.resolve().is_relative_to(root):
        raise ValueError("missing or escaped artifact")
    return current


def load_manifest(root):
    path = root / "manifest.json"
    if not path.is_file():
        raise AssertionError("missing maintenance-api/manifest.json: source package not imported")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest["schemaVersion"] != 1:
        raise ValueError("unknown manifest schema")
    if manifest["provenance"]["baselineCommit"] != BASELINE or manifest["provenance"]["sourceCommit"] != SOURCE:
        raise ValueError("wrong source lineage")
    overlay = manifest["overlay"]
    targets = manifest["targets"]
    if len(overlay) != 16 or len(targets) != 17:
        raise ValueError("incomplete source inventory")
    source_paths = set()
    target_paths = set()
    for entry in overlay:
        source = entry["source"]
        target = entry["target"]
        safe_relative(target)
        if not target.startswith(("app/src/main/java/com/termux/app/privateadb/", "app/src/test/java/com/termux/app/privateadb/", "contrib/private-adb/")):
            raise ValueError("unexpected target")
        if source != "overlay/" + target or source in source_paths or target in target_paths:
            raise ValueError("duplicate or remapped overlay")
        source_paths.add(source)
        target_paths.add(target)
        if sha256(checked_file(root, source).read_bytes()) != entry["sha256"]:
            raise ValueError("overlay byte drift")
    actual = {p.relative_to(root).as_posix() for p in (root / "overlay").rglob("*") if p.is_file()}
    if actual != source_paths:
        raise ValueError("unlisted overlay artifact")
    patch = manifest["patch"]
    fixture = manifest["fixture"]
    if patch["source"] != "patches/private-adb-service.patch" or patch["target"] != SERVICE:
        raise ValueError("unexpected patch")
    if fixture["source"] != "fixtures/PrivateAdbService.base.java" or fixture["target"] != SERVICE:
        raise ValueError("unexpected fixture")
    if fixture["sha256"] != FIXTURE_SHA256:
        raise ValueError("fixture does not bind the baseline Git blob")
    for entry in (patch, fixture):
        if sha256(checked_file(root, entry["source"]).read_bytes()) != entry["sha256"]:
            raise ValueError("patch or fixture byte drift")
    for directory, expected in (("patches", {patch["source"]}), ("fixtures", {fixture["source"]})):
        actual = {p.relative_to(root).as_posix() for p in (root / directory).rglob("*") if p.is_file()}
        if actual != expected:
            raise ValueError("unlisted patch or fixture")
    target_set = set()
    for entry in targets:
        safe_relative(entry["path"])
        if entry["path"] in target_set:
            raise ValueError("duplicate final target")
        target_set.add(entry["path"])
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or not re.fullmatch(r"[0-9a-f]{40}", entry["gitBlob"]):
            raise ValueError("invalid final identity")
    if target_set != target_paths | {SERVICE} or SERVICE in target_paths:
        raise ValueError("final inventory does not match overlay plus one patch")
    for entry in overlay:
        final = next(item for item in targets if item["path"] == entry["target"])
        if final["sha256"] != entry["sha256"]:
            raise ValueError("overlay and final identity disagree")
    return manifest


def stage(root, manifest, destination):
    for entry in manifest["overlay"]:
        target = destination / safe_relative(entry["target"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checked_file(root, entry["source"]), target)
    fixture = manifest["fixture"]
    target = destination / safe_relative(fixture["target"])
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(checked_file(root, fixture["source"]), target)


def git_apply(destination, patch, check=False):
    args = ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "apply"]
    if check:
        args.append("--check")
    args += ["--", str(patch.resolve())]
    return subprocess.run(args, cwd=destination, capture_output=True, check=False)


class OverlayTests(unittest.TestCase):
    def test_reconstructs_all_17_exact_source_files(self):
        manifest = load_manifest(ROOT)
        with tempfile.TemporaryDirectory(prefix="maintenance-overlay-") as temporary:
            destination = Path(temporary)
            stage(ROOT, manifest, destination)
            before = (destination / SERVICE).read_bytes()
            self.assertEqual(sha256(before), FIXTURE_SHA256)
            patch = checked_file(ROOT, manifest["patch"]["source"])
            checked = git_apply(destination, patch, check=True)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors="replace"))
            self.assertEqual((destination / SERVICE).read_bytes(), before)
            applied = git_apply(destination, patch)
            self.assertEqual(applied.returncode, 0, applied.stderr.decode(errors="replace"))
            actual = {p.relative_to(destination).as_posix(): p.read_bytes() for p in destination.rglob("*") if p.is_file()}
            self.assertEqual(set(actual), {entry["path"] for entry in manifest["targets"]})
            for entry in manifest["targets"]:
                with self.subTest(path=entry["path"]):
                    data = actual[entry["path"]]
                    self.assertEqual(sha256(data), entry["sha256"])
                    git_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
                    self.assertEqual(git_blob, entry["gitBlob"])

    def copy_package(self, destination):
        for directory in ("overlay", "patches", "fixtures"):
            shutil.copytree(ROOT / directory, destination / directory)
        shutil.copyfile(ROOT / "manifest.json", destination / "manifest.json")

    def save_manifest(self, destination, manifest):
        (destination / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def test_changed_patch_context_refuses_without_modifying_fixture(self):
        manifest = load_manifest(ROOT)
        with tempfile.TemporaryDirectory(prefix="maintenance-refusal-") as temporary:
            destination = Path(temporary)
            stage(ROOT, manifest, destination)
            service = destination / SERVICE
            original = service.read_bytes()
            patch_bytes = checked_file(ROOT, manifest["patch"]["source"]).read_bytes()
            context = b"     private long nextAttempt;\n"
            self.assertEqual(patch_bytes.count(context), 1)
            changed = patch_bytes.replace(context, b"     private long nonexistentBaselineMember;\n", 1)
            patch = destination / "changed.patch"
            patch.write_bytes(changed)
            for check in (True, False):
                with self.subTest(check=check):
                    result = git_apply(destination, patch, check=check)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"patch failed", result.stderr)
                    self.assertEqual(service.read_bytes(), original)

    def test_rejects_unsafe_paths(self):
        for value in ("", "/absolute", "../outside", "app/../outside", "app//file", "./file", "C:/file", "app\\file", "app/file:stream", "app/file\0", "https://host/file"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                safe_relative(value)
        self.assertEqual(safe_relative(SERVICE).as_posix(), SERVICE)

    def test_rejects_duplicate_or_remapped_overlay_targets(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-inventory-") as temporary:
            destination = Path(temporary)
            self.copy_package(destination)
            manifest = load_manifest(destination)
            manifest["overlay"][1] = dict(manifest["overlay"][0])
            self.save_manifest(destination, manifest)
            with self.assertRaisesRegex(ValueError, "duplicate or remapped"):
                load_manifest(destination)

    def test_rejects_missing_inventory_entry(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-inventory-") as temporary:
            destination = Path(temporary)
            self.copy_package(destination)
            manifest = load_manifest(destination)
            manifest["overlay"].pop()
            self.save_manifest(destination, manifest)
            with self.assertRaisesRegex(ValueError, "incomplete source inventory"):
                load_manifest(destination)

    def test_rejects_unlisted_artifacts(self):
        for directory in ("overlay", "patches", "fixtures"):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory(prefix="maintenance-extra-") as temporary:
                destination = Path(temporary)
                self.copy_package(destination)
                (destination / directory / "unlisted.txt").write_bytes(b"extra")
                with self.assertRaisesRegex(ValueError, "unlisted"):
                    load_manifest(destination)

    def test_rejects_overlay_patch_and_fixture_byte_drift(self):
        manifest = load_manifest(ROOT)
        entries = [manifest["overlay"][0], manifest["patch"], manifest["fixture"]]
        for entry in entries:
            with self.subTest(source=entry["source"]), tempfile.TemporaryDirectory(prefix="maintenance-drift-") as temporary:
                destination = Path(temporary)
                self.copy_package(destination)
                artifact = destination / entry["source"]
                artifact.write_bytes(artifact.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "byte drift"):
                    load_manifest(destination)

    def test_rejects_rebased_fixture_even_with_updated_manifest_hash(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-fixture-") as temporary:
            destination = Path(temporary)
            self.copy_package(destination)
            manifest = load_manifest(destination)
            artifact = destination / manifest["fixture"]["source"]
            artifact.write_bytes(artifact.read_bytes() + b"\n")
            manifest["fixture"]["sha256"] = sha256(artifact.read_bytes())
            self.save_manifest(destination, manifest)
            with self.assertRaisesRegex(ValueError, "baseline Git blob"):
                load_manifest(destination)

    def test_rejects_wrong_lineage(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-lineage-") as temporary:
            destination = Path(temporary)
            self.copy_package(destination)
            manifest = load_manifest(destination)
            manifest["provenance"]["baselineCommit"] = "0" * 40
            self.save_manifest(destination, manifest)
            with self.assertRaisesRegex(ValueError, "wrong source lineage"):
                load_manifest(destination)

    def test_rejects_duplicate_final_targets(self):
        with tempfile.TemporaryDirectory(prefix="maintenance-targets-") as temporary:
            destination = Path(temporary)
            self.copy_package(destination)
            manifest = load_manifest(destination)
            manifest["targets"][1] = dict(manifest["targets"][0])
            self.save_manifest(destination, manifest)
            with self.assertRaisesRegex(ValueError, "duplicate final target"):
                load_manifest(destination)


if __name__ == "__main__":
    unittest.main()
