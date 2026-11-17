"""Repeatable acceptance checks with isolated Bitbucket and Nexus fixtures."""
import argparse
import contextlib
import csv
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import bitbucket_inventory as bitbucket
import nexus_inventory as nexus
from inventory_common import Api, classify, parse_java_majors, write_reports
from web_app import make_flags, results_page, stats, update_stats


VERSIONS = {
    "17.0.5": "outside_scope", "17.0.6+10": "candidate", "17.0.10+7": "candidate",
    "17": "unknown_version", "21.0.5": "outside_scope", "1.8.0_252": "outside_scope",
}


def tar_fixture(path, files):
    with tarfile.open(path, "w") as archive:
        for name, contents in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))


def bb_args(**overrides):
    return argparse.Namespace(**({"project": [], "branch": [], "max_file_bytes": 1024, "java_majors": (17,),
                                  "workspace": "test"} | overrides))


class VersionTests(unittest.TestCase):
    def test_selected_majors_preserve_java_17_threshold(self):
        majors = parse_java_majors("27, 17, 21, 25,21")
        self.assertEqual(majors, (17, 21, 25, 27))
        for version, status in (("17.0.5", "outside_scope"), ("17", "unknown_version"),
                                ("17.0.6", "candidate"), ("21", "candidate"),
                                ("25.0.1", "candidate"), ("27-ea+3", "candidate"),
                                ("11.0.22", "outside_scope")):
            self.assertEqual(classify(version, majors)[1], status, version)
        self.assertEqual(classify("1.8.0_252", (8,))[1], "candidate")
        for invalid in ("", "17,25.0", "17,,21", "123"):
            with self.assertRaises(ValueError):
                parse_java_majors(invalid)

    def test_java_version_policy(self):
        for version, status in VERSIONS.items():
            with self.subTest(version=version):
                self.assertEqual(classify(version), (version, status))

    def test_docker_stages_and_maven_properties(self):
        dockerfile = """ARG JAVA_VERSION=17.0.6
FROM amazoncorretto:${JAVA_VERSION} AS build
FROM eclipse-temurin:17-jre
"""
        findings = list(bitbucket.declarations("Dockerfile", dockerfile))
        self.assertEqual([(row["role"], row["status"]) for row in findings],
                         [("intermediate_base", "candidate"), ("runtime_base", "unknown_version")])
        pom = """<project><properties><jdk.version>17.0.10</jdk.version></properties>
<configuration><release>${jdk.version}</release></configuration></project>"""
        findings = list(bitbucket.declarations("pom.xml", pom))
        self.assertEqual([(row["role"], row["version"], row["line"]) for row in findings],
                         [("build_jdk_declaration", "17.0.10", 1),
                          ("bytecode_target", "17.0.10", 2)])

    def test_gradle_and_ci_jdk_declarations(self):
        content = "java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }"
        row, = bitbucket.declarations("build.gradle.kts", content)
        self.assertEqual((row["role"], row["version"], row["status"]),
                         ("build_jdk_declaration", "17", "unknown_version"))
        row, = bitbucket.declarations("Jenkinsfile", "tools { jdk 'jdk-17.0.7' }")
        self.assertEqual((row["version"], row["status"]), ("17.0.7", "candidate"))
        row, = bitbucket.declarations("Dockerfile", "FROM gradle:8.14.3-jdk17")
        self.assertEqual((row["version"], row["status"]), ("17", "unknown_version"))


class BitbucketTests(unittest.TestCase):
    def test_datacenter_pagination_commit_and_delay(self):
        events = []
        commit = "a" * 40

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                url = urlsplit(self.path)
                query = parse_qs(url.query)
                events.append((url.path, query, time.monotonic()))
                if url.path.endswith("/raw/pom.xml"):
                    body = b"<project><properties><java.version>17.0.6</java.version></properties></project>"
                elif url.path.endswith("/raw/Dockerfile"):
                    self.send_error(403)
                    return
                else:
                    page = {"isLastPage": True}
                    if url.path.endswith("/branches"):
                        page["values"] = [{"default": True, "latestCommit": commit, "displayId": "main"}]
                    elif url.path.endswith("/files"):
                        page["values"] = ["pom.xml", "Dockerfile"]
                    elif query.get("start") == ["5"]:
                        page["values"] = [{"slug": "fixture", "project": {"key": "TEST"}}]
                    else:
                        page.update(values=[], isLastPage=False, nextPageStart=5)
                    body = json.dumps(page).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                api = Api(f"http://127.0.0.1:{server.server_port}", None, 5, delay=0.1, progress=True)
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    assets, findings, errors = bitbucket.inventory(api, bb_args())
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual((len(assets), len(findings), len(errors)), (1, 1, 1))
        self.assertEqual((assets[0]["commit"], assets[0]["status"]), (commit, "partial"))
        self.assertEqual(findings[0]["status"], "candidate")
        self.assertEqual(len(events), 6)
        self.assertEqual([event[1]["at"] for event in events[3:]], [[commit]] * 3)
        intervals = [right[2] - left[2] for left, right in zip(events, events[1:])]
        self.assertTrue(all(interval >= 0.095 for interval in intervals), intervals)
        progress = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([row["http_status"] for row in progress], [200] * 5 + [403])

    def test_cloud_branch_and_nested_file(self):
        commit = "b" * 40
        root = "/repositories/test/repo"
        tree = root + "/src/" + commit + "/"
        endpoints = {
            "/repositories/test?pagelen=100": {
                "values": [{"slug": "repo", "project": {"key": "TEST"}, "mainbranch": {"name": "main"}}]
            },
            root + "/refs/branches/main": {"name": "main", "target": {"hash": commit}},
            tree + "?pagelen=100": {"values": [{"type": "commit_directory", "path": "nested"}]},
            tree + "nested/?pagelen=100": {"values": [{"type": "commit_file", "path": "nested/.java-version"}]},
        }

        class Cloud:
            base = "https://example.invalid/2.0"

            def json(self, path):
                return endpoints[path]

            def read(self, path, *_args, **_kwargs):
                if path != tree + "nested/.java-version":
                    raise AssertionError(path)
                return b"17.0.6"

        assets, findings, errors = bitbucket.cloud_inventory(Cloud(), bb_args(project=["TEST"]))
        self.assertFalse(errors)
        self.assertEqual(len(assets), 1)
        self.assertEqual((findings[0]["commit"], findings[0]["status"]), (commit, "candidate"))
        endpoints["/repositories/test?pagelen=100"]["next"] = "https://other.invalid/2.0/repos"
        _, _, errors = bitbucket.cloud_inventory(Cloud(), bb_args())
        self.assertIn("attempted to leave", errors[0]["error"])


class NexusTests(unittest.TestCase):
    def test_release_requires_runtime_and_unknown_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "rootfs.tar")
            tar_fixture(archive, {
                "./jre/release": b'JAVA_VERSION="17.0.6"\nJAVA_RUNTIME_VERSION="17.0.6+10"\nIMPLEMENTOR="Fixture"\n',
                "./jre/bin/java": b"fixture",
                "./unknown/lib/server/libjvm.so": b"fixture",
                "./metadata/release": b'JAVA_VERSION="17.0.13"\n',
            })
            findings = nexus.java_files(archive)
        self.assertEqual([(r["version"], r["status"]) for r in findings],
                         [("17.0.6+10", "candidate"), ("", "unknown_version")])
        self.assertEqual(findings[0]["vendor"], "Fixture")

    def test_deduplicate_manifest_alias_keep_untagged_digest(self):
        tagged_digest = "sha256:" + "1" * 64
        untagged_digest = "sha256:" + "2" * 64

        class NexusApi:
            def json(self, path, params=None):
                if path.endswith("/repositories"):
                    return [{"name": "hosted", "format": "docker", "type": "hosted"}]
                if "continuationToken" not in params:
                    return {"items": [{"path": f"v2/example/service/manifests/{tagged_digest}"},
                                      {"path": "v2/example/service/manifests/alpha"}], "continuationToken": "next"}
                return {"items": [{"path": f"v2/example/service/manifests/{untagged_digest}"}]}

        class Registry:
            def __init__(self):
                self.exported = []

            def run(self, command, ref, insecure, *options):
                if command == "digest":
                    return tagged_digest.encode()
                self.exported.append(ref.rsplit("@", 1)[1])
                tar_fixture(options[0], {"jre/release": b'JAVA_VERSION="17.0.10"', "jre/bin/java": b"test"})

            def manifests(self, name, digest, insecure):
                yield digest, "linux/amd64"

        registry = Registry()
        with tempfile.TemporaryDirectory() as directory:
            assets, findings, errors = nexus.inventory(
                NexusApi(), registry, argparse.Namespace(repository=[], include_proxy=False, java_majors=(17,)),
                {"hosted": "registry.example:5000"}, directory)
        self.assertFalse(errors)
        self.assertEqual(registry.exported, [tagged_digest, untagged_digest])
        self.assertEqual([(row["tag"], row["digest"]) for row in assets],
                         [("alpha", tagged_digest), ("", untagged_digest)])
        self.assertEqual(len(findings), 2)

    def test_manifest_index_skips_attestations(self):
        index = "sha256:" + "0" * 64

        class FixtureRegistry(nexus.Registry):
            def __init__(self):
                pass

            def run(self, command, ref, insecure, *_):
                if ref.endswith(index):
                    return json.dumps({"manifests": [
                        {"digest": "sha256:" + digit * 64,
                         "platform": {"os": "linux", "architecture": arch}}
                        for digit, arch in (("1", "amd64"), ("2", "arm64"))]
                        + [{"digest": "sha256:" + "3" * 64,
                            "annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]
                    }).encode()
                self.assert_image(ref)
                return b'{"config":{"mediaType":"application/vnd.oci.image.config.v1+json"},"layers":[]}'

            @staticmethod
            def assert_image(ref):
                if ref.endswith("3" * 64):
                    raise AssertionError("Attestation queried as an image")

        self.assertEqual([platform for _, platform in FixtureRegistry().manifests(
            "registry.invalid/example", index, False)], ["linux/amd64", "linux/arm64"])


class ConsoleTests(unittest.TestCase):
    def test_results_pages_group_repositories_and_encode_links(self):
        findings = [
            {"repository": f"workspace/repo-{index:02}", "evidence": "ci config/pom.xml (java.version)",
             "commit": "abc", "line": 5, "status": "candidate" if index <= 11 else "outside_scope"}
            for index in range(1, 24)
        ]
        findings.append(findings[0].copy())
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            output = Path(tmp)
            write_reports(output / "bitbucket" / "run", {
                "source": "bitbucket", "provider": "cloud", "url": "https://api.bitbucket.org/2.0",
                "java_majors": [17, 21],
            }, [], findings, [])
            write_reports(output / "nexus" / "run", {"source": "nexus", "url": "http://host.docker.internal:18182"},
                          [], [{"repository": "test-repo", "image": "foo/image", "reference": "25",
                                "status": "candidate"}], [])
            with patch("web_app.OUTPUT", output):
                first = results_page("bitbucket", 1, False)
                second = results_page("bitbucket", 2, True)
                last = results_page("bitbucket", 3, False)
                image, = results_page("nexus", 1, False)["items"]
        self.assertEqual((len(first["items"]), len(last["items"]), first["pages"]), (10, 3, 3))
        self.assertEqual((second["total"], len(second["items"])), (11, 1))
        self.assertEqual(first["javaMajors"], [17, 21])
        group = first["items"][0]
        self.assertEqual(group["url"], "https://bitbucket.org/workspace/repo-01")
        self.assertEqual(len(group["findings"]), 2)
        self.assertTrue(group["findings"][0]["url"].endswith("/src/abc/ci%20config/pom.xml#lines-5"))
        self.assertEqual(image["url"], "http://127.0.0.1:18182/#browse/browse:test-repo:v2%2Ffoo%2Fimage%2Fmanifests%2F25")

    def test_progress_aggregation_and_fractional_delay(self):
        row = stats()
        update_stats(row, {"seconds": 0.05, "ok": True, "operation": "/repos", "http_status": 200})
        update_stats(row, {"seconds": 0.1, "ok": False, "operation": "/branches", "http_status": 403})
        self.assertEqual((row["count"], row["errors"], row["last"], row["max"], row["http_status"]),
                         (2, 1, 0.1, 0.1, 403))
        self.assertAlmostEqual(row["total"], 0.15)
        self.assertEqual(make_flags("bitbucket", {"provider": "cloud", "delay": 0.1, "projects": "A, B"}),
                         ["--delay=0.1", "--provider=cloud", "--project=A", "--project=B"])
        self.assertIn("--java-majors=21,27", make_flags("nexus", {"javaMajors": "27,21"}))
        with self.assertRaises(ValueError):
            make_flags("nexus", {"delay": "nan"})

    def test_reports_contain_all_statuses_csv_candidates_only(self):
        rows = [{"repository": "=cmd", "version": v, "status": status}
                for v, status in VERSIONS.items()]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(write_reports(tmp, {}, [], rows, []), 0)
            report = json.loads(Path(tmp, "inventory.json").read_text(encoding="utf-8"))
            with Path(tmp, "candidates.csv").open(encoding="utf-8-sig", newline="") as stream:
                candidates = list(csv.DictReader(stream))
        self.assertEqual(report["findings"], rows)
        self.assertEqual({row["version"] for row in candidates}, {"17.0.6+10", "17.0.10+7"})
        self.assertTrue(all(row["repository"] == "'=cmd" for row in candidates))


if __name__ == "__main__":
    unittest.main()
