"""Repeatable acceptance checks with isolated Bitbucket and Nexus fixtures."""
import argparse
import base64
import contextlib
import csv
import io
import json
import os
import subprocess
from pathlib import Path
import tarfile
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.error import URLError
from unittest.mock import patch

import bitbucket_inventory as bitbucket
import nexus_inventory as nexus
from inventory_common import (
    Api, ApiHttpError, ApiTimeoutError, JAVA4SHELL_MAJORS, classify, java4shell_result,
    parse_java_majors, write_reports,
)
from web_app import diagnostic, make_flags, results_page, run_job, stats, update_stats


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
                                  "profile": "inventory", "provider": "datacenter", "git_timeout": 10,
                                  "git_auth": None, "progress": True,
                                  "workspace": "test"} | overrides))


class VersionTests(unittest.TestCase):
    def test_java4shell_oracle_advisory_versions_and_fixed_baselines(self):
        affected = ("8u511b33-perf", "1.8.0_511-b33-perf", "17.0.21.0.3",
                    "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3", "21.3.20.0.3")
        for version in affected:
            with self.subTest(version=version):
                self.assertEqual(classify(version, JAVA4SHELL_MAJORS)[0], version)
                self.assertEqual(java4shell_result({"vendor": "Oracle Corporation", "version": version})[0],
                                 "candidate")
        self.assertEqual(java4shell_result({"version": "11.0.33", "product_version": "21.3.20.0.3"})[0],
                         "candidate")
        for version in ("1.8.0_513-b04", "17.0.21.1+4", "21.0.13.1", "25.0.5.1", "27.0.1.1", "11.0.33", "17.0.5"):
            self.assertEqual(java4shell_result({"vendor": "Oracle Corporation", "version": version})[0],
                             "outside_scope", version)
        self.assertEqual(java4shell_result({"vendor": "Eclipse Adoptium", "version": "17.0.21.1+4"})[0],
                         "candidate")
        self.assertEqual(java4shell_result({"vendor": "Oracle Corporation", "distribution": "GraalVM",
                                           "version": "21.0.13.1"})[0], "candidate")
        row, = bitbucket.declarations("Dockerfile", "FROM oracle/jdk:17.0.21.0.3", JAVA4SHELL_MAJORS)
        self.assertEqual((row["vendor"], row["version"]), ("Oracle", "17.0.21.0.3"))

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
    @staticmethod
    def git(repo, *command):
        return subprocess.check_output(
            ["git", "-C", str(repo), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *command],
            stderr=subprocess.PIPE,
        ).decode().strip()

    def test_one_clone_stops_after_first_candidate_repository_file(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory, "repo")
            repo.mkdir()

            def git(*command):
                return self.git(repo, *command)

            git("init", "-b", "main")
            (repo / "Dockerfile").write_text(
                "FROM registry.example/eclipse-temurin:8-jdk-noble AS jdk8\n"
                "FROM registry.example/eclipse-temurin:21-jdk-noble AS jdk21\n"
                "FROM registry.example/maven:3.9-eclipse-temurin-17\n"
                "COPY --from=jdk21 /opt/java/openjdk/ /opt/toolchains/21/\n",
                encoding="utf-8",
            )
            extra = repo / "nested"
            extra.mkdir()
            (extra / ".java-version").write_text("25.0.1", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "Main")
            commit = git("rev-parse", "HEAD")
            git("checkout", "-b", "release")
            (repo / "Dockerfile").write_text("FROM eclipse-temurin:27", encoding="utf-8")
            git("commit", "-am", "Release")
            git("checkout", "main")
            args = bb_args(java_majors=JAVA4SHELL_MAJORS, profile="java4shell", branch=["*"])
            asset, findings, errors = {}, [], []
            with contextlib.redirect_stdout(io.StringIO()) as log:
                bitbucket.scan_repository(args, repo.as_uri(), None, asset, findings, errors)

        self.assertFalse(errors)
        self.assertEqual((asset["branch"], asset["commit"], asset["candidate"]), ("main", commit, True))
        self.assertEqual(len(log.getvalue().splitlines()), 1)
        self.assertEqual([(row["file"], row["version"], row["role"], row["status"]) for row in findings],
                         [("Dockerfile", "8", "intermediate_base", "outside_scope"),
                          ("Dockerfile", "21", "bundled_jdk", "candidate")])
        self.assertEqual(findings[-1]["java_major"], 21)

    def test_unchanged_file_across_branches_is_scanned_once(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-b", "main")
            (repo / ".java-version").write_text("17.0.5", encoding="utf-8")
            (repo / "Dockerfile").write_text("FROM eclipse-temurin:17.0.5\n", encoding="utf-8")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "Main")
            self.git(repo, "checkout", "-b", "release")
            (repo / "Dockerfile").write_text("FROM eclipse-temurin:17.0.6\n", encoding="utf-8")
            self.git(repo, "commit", "-am", "Release")
            self.git(repo, "checkout", "main")
            args = bb_args(branch=["release"], progress=False)
            asset, findings, errors = {}, [], []
            with patch.object(bitbucket, "declarations", wraps=bitbucket.declarations) as parse:
                bitbucket.scan_repository(args, repo.as_uri(), None, asset, findings, errors)

        self.assertFalse(errors)
        self.assertEqual([call.args[0] for call in parse.call_args_list],
                         [".java-version", "Dockerfile", "Dockerfile"])
        self.assertEqual([(row["branch"], row["file"], row["version"]) for row in findings],
                         [("main", ".java-version", "17.0.5"),
                          ("main", "Dockerfile", "17.0.5"),
                          ("release", "Dockerfile", "17.0.6")])
        self.assertTrue(asset["candidate"])

    def test_datacenter_catalog_pagination_and_delay(self):
        events = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                url = urlsplit(self.path)
                query = parse_qs(url.query)
                events.append((url.path, query, time.monotonic()))
                if query.get("start") == ["5"]:
                    body = {"values": [{"slug": "fixture", "project": {"key": "TEST"}}], "isLastPage": True}
                else:
                    body = {"values": [], "isLastPage": False, "nextPageStart": 5}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                api = Api(f"http://127.0.0.1:{server.server_port}/bitbucket", None, 5, delay=0.1, progress=True)
                with contextlib.redirect_stdout(io.StringIO()), patch.object(bitbucket, "scan_repository") as scan:
                    assets, _, errors = bitbucket.inventory(api, bb_args())
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual((len(assets), len(errors)), (1, 0))
        self.assertEqual([event[0] for event in events], ["/bitbucket/rest/api/latest/repos"] * 2)
        self.assertGreaterEqual(events[1][2] - events[0][2], 0.095)
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[1:3], (api.base + "/scm/test/fixture.git", None))

    def test_cloud_catalog_is_the_only_api_call(self):
        calls = []

        class Cloud:
            base = "https://api.bitbucket.org/2.0"

            def json(self, path):
                calls.append(path)
                return {"values": [{"slug": "repo", "project": {"key": "TEST"}, "mainbranch": {"name": "main"}}]}

        with patch.object(bitbucket, "scan_repository") as scan:
            assets, _, errors = bitbucket.inventory(Cloud(), bb_args(provider="cloud", project=["TEST"]))
        self.assertFalse(errors)
        self.assertEqual(calls, ["/repositories/test?pagelen=100"])
        self.assertEqual(len(assets), 1)
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[1:3], ("https://bitbucket.org/test/repo.git", "main"))


class NexusTests(unittest.TestCase):
    def test_api_timeouts_are_distinct_from_connection_errors(self):
        api = Api("https://nexus.invalid", None, 1)
        for failure in (TimeoutError("read deadline"), URLError(TimeoutError("connect deadline"))):
            with patch.object(api.opener, "open", side_effect=failure):
                with self.assertRaisesRegex(ApiTimeoutError, "Request timed out at /service/rest/v1/assets"):
                    api.json("/service/rest/v1/assets")

    def test_extdirect_discovers_tags_and_digests_when_rest_is_blocked(self):
        digest = "sha256:" + "a" * 64
        tree = {
            "v2": [("v2/blobs", False), ("v2/team", False)],
            "v2/team": [("v2/team/image", False)],
            "v2/team/image": [("v2/team/image/tags", False), ("v2/team/image/manifests", False)],
            "v2/team/image/tags": [("v2/team/image/tags/1.0", True)],
            "v2/team/image/manifests": [("v2/team/image/manifests/" + digest.replace(":", "%3A"), True)],
        }
        repository = {"name": "images", "format": "docker", "type": "hosted"}
        calls = []

        class FixtureApi:
            base = "https://nexus.invalid"
            failure = ApiHttpError(404, "/service/rest/v1/assets")

            def json(self, path, params=None):
                raise self.failure

            def read(self, path, *, data, extra_headers):
                self_test.assertEqual(path, "/service/extdirect")
                csrf = extra_headers["NX-ANTI-CSRF-TOKEN"]
                self_test.assertEqual(extra_headers["Cookie"], f"NX-ANTI-CSRF-TOKEN={csrf}")
                payload = json.loads(data)
                action, method = payload["action"], payload["method"]
                params, = payload["data"]
                calls.append((action, method, params))
                if action == "coreui_Repository":
                    entries = [repository]
                else:
                    entries = [{"id": node, "leaf": leaf} for node, leaf in tree[params["node"]]]
                return json.dumps({"result": {"success": True, "data": entries}}).encode()

        self_test = self
        api = FixtureApi()
        self.assertEqual(nexus.repository_catalog(api, "auto"), [repository])
        self.assertEqual({row["path"] for row in nexus.repository_assets(api, "images", "auto")},
                         {"v2/team/image/tags/1.0", "v2/team/image/manifests/" + digest})
        self.assertIn(("coreui_Browse", "read", {"repositoryName": "images", "node": "v2"}), calls)
        with self.assertRaises(ApiHttpError):
            list(nexus.repository_assets(api, "images", "rest"))
        api.failure = ApiTimeoutError("Request timed out")
        self.assertEqual(nexus.repository_catalog(api, "auto"), [repository])
        self.assertEqual(len(list(nexus.repository_assets(api, "images", "auto"))), 2)
        with self.assertRaises(ApiTimeoutError):
            list(nexus.repository_assets(api, "images", "rest"))
        api.failure = RuntimeError("DNS lookup failed")
        with self.assertRaisesRegex(RuntimeError, "DNS lookup failed"):
            nexus.repository_catalog(api, "auto")
        self.assertEqual(len(list(nexus.repository_assets(api, "images", "auto"))), 2)

    def test_path_based_routing_and_explicit_override(self):
        digest = "sha256:" + "a" * 64

        class FixtureApi:
            base = "https://nexus.example.invalid"

            def json(self, path, params=None):
                if path.endswith("/repositories"):
                    return [{"name": repo, "format": "docker", "type": "hosted"}
                            for repo in ("auto-hosted", "port-hosted")]
                return {"items": [{"path": "v2/team/demo/manifests/1.0"}]}

        class FixtureRegistry:
            def __init__(self):
                self.tags = []

            def run(self, command, ref, insecure, *options):
                if command == "digest":
                    self.tags.append(ref)
                    return digest.encode()
                tar_fixture(options[0], {})

            def manifests(self, name, digest, insecure, *, on_error=None):
                yield digest, "linux/amd64"

        registry = FixtureRegistry()
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(repository=[], include_proxy=False, java_majors=(17,), discovery="rest")
            assets, _, errors = nexus.inventory(
                FixtureApi(), registry, args, {"port-hosted": "https://nexus.example.invalid:18443"}, tmp
            )
        self.assertFalse(errors)
        self.assertEqual(len(assets), 2)
        self.assertEqual(registry.tags, ["nexus.example.invalid/auto-hosted/team/demo:1.0",
                                         "nexus.example.invalid:18443/team/demo:1.0"])

    def test_credentials_follow_the_resolved_registry_host(self):
        env = {"NEXUS_DOCKER_USERNAME": "reader", "NEXUS_DOCKER_PASSWORD": "fixture",
               "NEXUS_ALLOW_HTTP_AUTH": "0"}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env):
            registry = nexus.Registry(argparse.Namespace(crane="crane", scan_timeout=5, progress=False), tmp)
            with patch("nexus_inventory.subprocess.run") as run:
                run.return_value = argparse.Namespace(returncode=0, stdout=b"result")
                registry.run("digest", "nexus.example.invalid/auto-hosted/team/demo:1.0", False)
                settings = json.loads(Path(tmp, "config.json").read_text(encoding="utf-8"))
                self.assertEqual(base64.b64decode(settings["auths"]["nexus.example.invalid"]["auth"]),
                                 b"reader:fixture")
                self.assertEqual(run.call_args.kwargs["env"]["DOCKER_CONFIG"], tmp)
                with self.assertRaisesRegex(ValueError, "require HTTPS"):
                    registry.run("digest", "nexus.example.invalid/auto-hosted/team/demo:1.0", True)
                self.assertEqual(run.call_count, 1)

    def test_requested_non_docker_repository_has_distinct_diagnostic(self):
        class NexusApi:
            def json(self, path):
                if path != "/service/rest/v1/repositories":
                    raise AssertionError(path)
                return [{"name": "maven-hosted", "format": "maven2", "type": "hosted"}]

        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(repository=["maven-hosted", "unlisted"], include_proxy=False, discovery="rest")
            assets, findings, errors = nexus.inventory(NexusApi(), None, args, {}, tmp)
        self.assertEqual((assets, findings), ([], []))
        self.assertIn("format is 'maven2'", errors[0]["error"])
        self.assertIn("missing from the Nexus catalog", errors[1]["error"])

    def test_java4shell_report_reads_graalvm_product_version_separately(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            archive = Path(directory, "rootfs.tar")
            tar_fixture(archive, {
                "opt/jdk/release": b'JAVA_VERSION="11.0.33"\nGRAALVM_VERSION="21.3.20.0.3"\n',
                "opt/jdk/bin/java": b"fixture",
            })
            rows = nexus.java_files(archive, JAVA4SHELL_MAJORS)
            self.assertEqual(rows[0]["status"], "outside_scope")
            write_reports(directory, {"profile": "java4shell"}, [], rows, [])
            report = json.loads(Path(directory, "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["candidates"], 1)
        self.assertEqual(report["findings"][0]["product_version"], "21.3.20.0.3")

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

            def manifests(self, name, digest, insecure, *, on_error=None):
                yield digest, "linux/amd64"

        registry = Registry()
        with tempfile.TemporaryDirectory() as directory:
            assets, findings, errors = nexus.inventory(
                NexusApi(), registry, argparse.Namespace(repository=[], include_proxy=False, java_majors=(17,),
                                                         discovery="rest"),
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

    def test_missing_platform_manifest_preserves_remaining_findings(self):
        index, missing, available = ("sha256:" + digit * 64 for digit in ("0", "1", "2"))

        class FixtureApi:
            def json(self, path, params=None):
                if path.endswith("/repositories"):
                    return [{"name": "hosted", "format": "docker", "type": "hosted"}]
                return {"items": [{"path": "v2/service/manifests/latest"}]}

        class FixtureRegistry(nexus.Registry):
            def __init__(self):
                pass

            def run(self, command, ref, insecure, *options):
                if command == "digest":
                    return index.encode()
                if command == "export":
                    tar_fixture(options[0], {"jdk/release": b'JAVA_VERSION="17.0.10"', "jdk/bin/java": b"test"})
                elif ref.endswith(index):
                    return json.dumps({"manifests": [
                        {"digest": digest, "platform": {"os": "linux", "architecture": architecture}}
                        for digest, architecture in ((missing, "amd64"), (available, "arm64"))
                    ]}).encode()
                elif ref.endswith(missing):
                    raise RuntimeError("manifest returned 404")
                else:
                    return b'{"config":{"mediaType":"application/vnd.oci.image.config.v1+json"},"layers":[]}'

        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(repository=[], include_proxy=False, java_majors=(17,), discovery="rest")
            assets, findings, errors = nexus.inventory(
                FixtureApi(), FixtureRegistry(), args, {"hosted": "registry.invalid"}, directory
            )
        self.assertEqual([(row["digest"], row["status"]) for row in assets],
                         [(missing, "error"), (available, "scanned")])
        self.assertEqual([(row["platform"], row["status"]) for row in findings],
                         [("linux/arm64", "candidate")])
        self.assertEqual((errors[0]["platform"], errors[0]["stage"]), ("linux/amd64", "read_platform_manifest"))


class ConsoleTests(unittest.TestCase):
    def test_debug_logs_every_operation_without_url_parameters(self):
        job = {"id": "fixture", "started": time.monotonic(), "http": stats(), "registry": stats(),
               "messages": [], "diagnostics": [], "provider": "nexus", "debug": True}
        events = [
            {"event": "http", "operation": "/repositories?continuationToken=private", "http_status": 200,
             "target": "https://nexus.example.invalid", "ok": True, "seconds": 0.02},
            {"event": "registry", "operation": "export registry.example.invalid/demo",
             "ok": True, "seconds": 1.5},
            *[{"event": "http", "operation": "/assets", "http_status": 403, "ok": False,
               "seconds": 0.1} for _ in range(22)],
        ]
        with tempfile.TemporaryDirectory() as tmp, self.assertLogs("inventory", level="DEBUG") as log:
            with patch("web_app.OUTPUT", Path(tmp)), patch("web_app.subprocess.Popen") as popen:
                process = popen.return_value.__enter__.return_value
                process.stdout = [json.dumps(event) for event in events]
                process.wait.return_value = 2
                run_job("nexus", job, [])
        output = "\n".join(log.output)
        self.assertIn("GET https://nexus.example.invalid/repositories", output)
        self.assertIn("export registry.example.invalid/demo", output)
        self.assertNotIn("continuationToken", output)
        self.assertEqual(output.count("GET /assets"), 22)
        self.assertEqual(len(job["diagnostics"]), 1)

    def test_datacenter_failure_reports_cause_and_logs_redacted_diagnostics(self):
        job = {"id": "fixture", "started": time.monotonic(), "http": stats(), "registry": stats(),
               "messages": [], "diagnostics": [], "provider": "datacenter", "debug": True}
        with tempfile.TemporaryDirectory() as tmp, self.assertLogs("inventory", level="DEBUG") as log:
            env = {"BITBUCKET_TOKEN": "fixture-secret", "BITBUCKET_ALLOW_HTTP_AUTH": "0"}
            with patch("web_app.OUTPUT", Path(tmp)), patch.dict(os.environ, env):
                run_job("bitbucket", job, ["--provider=datacenter", "--url=http://127.0.0.1:1"])
                diagnostic("bitbucket", job, "failed with fixture-secret")
        self.assertEqual(job["state"], "failed")
        self.assertTrue(any("Authenticated REST requests require HTTPS" in line for line in job["diagnostics"]))
        self.assertIn("exit=2", "\n".join(log.output))
        self.assertNotIn("fixture-secret", "\n".join(log.output))

    def test_results_pages_group_repositories_and_encode_links(self):
        findings = [
            {"repository": f"workspace/repo-{index:02}", "evidence": "ci config/pom.xml (java.version)",
             "commit": "abc", "line": 5, "version": "21",
             "status": "candidate" if index <= 11 else "outside_scope"}
            for index in range(1, 24)
        ]
        findings.insert(0, {**findings[0], "status": "unknown_version", "line": 2})
        findings.append({**findings[1], "version": "25", "line": 9})
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
        self.assertEqual((len(first["items"]), len(last["items"]), first["pages"]), (10, 1, 2))
        self.assertEqual((second["total"], len(second["items"])), (11, 1))
        self.assertEqual(first["javaMajors"], [17, 21])
        group = first["items"][0]
        self.assertEqual(group["url"], "https://bitbucket.org/workspace/repo-01")
        finding, = group["findings"]
        self.assertEqual((finding["status"], finding["version"]), ("candidate", "21"))
        self.assertTrue(finding["url"].endswith("/src/abc/ci%20config/pom.xml#lines-5"))
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
