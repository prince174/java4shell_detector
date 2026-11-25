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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from unittest.mock import patch

import bitbucket_inventory as bitbucket
import nexus_inventory as nexus
from inventory_common import (
    Api, ApiHttpError, ApiTimeoutError, JAVA4SHELL_MAJORS, classify, java4shell_result,
    parse_java_majors, write_reports,
)
from web_app import Handler as WebHandler, diagnostic, make_flags, results_page, run_job, stats, update_stats


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

    def test_asdf_java_alternatives_support_tabs_and_inline_comments(self):
        text = "nodejs 22.0.0\njava\ttemurin-17.0.5  temurin-17.0.6+10 # 21.0.1\n"
        rows = list(bitbucket.declarations(".tool-versions", text))
        self.assertEqual(
            [(row["line"], row["version"], row["status"], row["role"]) for row in rows],
            [(2, "17.0.5", "outside_scope", "build_jdk_declaration"),
             (2, "17.0.6+10", "candidate", "build_jdk_declaration")],
        )

    def test_docker_json_copy_detects_jdk_bundled_in_final_stage(self):
        dockerfile = """FROM eclipse-temurin:17.0.6 AS tools
FROM eclipse-temurin:17.0.5 AS old
COPY --from=tools ["/opt/java/openjdk/", "/scratch/"]
FROM debian:stable
COPY --from=old ["/opt/java/openjdk/bin/java", "/usr/local/bin/java"]
COPY --from=TOOLS ["/opt/java/openjdk/", "/runtime jdk/"]
"""
        rows = list(bitbucket.declarations("Dockerfile", dockerfile))
        self.assertEqual(
            [(row["line"], row["version"], row["status"], row["role"]) for row in rows],
            [(1, "17.0.6", "candidate", "bundled_jdk"),
             (2, "17.0.5", "outside_scope", "intermediate_base")],
        )

    def test_docker_copy_checks_all_sources_but_excludes_destination(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        cases = [
            ("/opt/artifacts /opt/java/openjdk/ /runtime/", "bundled_jdk"),
            ('["/opt/artifacts", "/opt/java/openjdk/", "/runtime/"]', "bundled_jdk"),
            ("/opt/artifacts /runtime/jdk/", "intermediate_base"),
            ('["/opt/artifacts", "/runtime/jdk/"]', "intermediate_base"),
        ]
        for arguments, role in cases:
            with self.subTest(arguments=arguments):
                row, = bitbucket.declarations("Dockerfile", base + f"COPY --from=tools {arguments}")
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (1, "17.0.6", "candidate", role))

    def test_yaml_inline_java_versions_preserve_threshold_and_role(self):
        for path in ("build.yml", "build.yaml"):
            with self.subTest(path=path):
                rows = list(bitbucket.declarations(path,
                    '\n  java-version: [17.0.5, 17.0.6, "21", \'11\'] # build matrix', (17, 21)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("17.0.5", "outside_scope", "build_jdk_declaration", 2),
                                  ("17.0.6", "candidate", "build_jdk_declaration", 2),
                                  ("21", "candidate", "build_jdk_declaration", 2),
                                  ("11", "outside_scope", "build_jdk_declaration", 2)])

    def test_yaml_multiline_java_list_preserves_opening_line(self):
        text = ('matrix:\n  java-version: [\n    17.0.5, # below threshold\n'
                '    "17.0.6",\n    \'21\'\n  ]\n')
        for path in ("build.yml", "build.yaml"):
            with self.subTest(path=path):
                rows = list(bitbucket.declarations(path, text, (17, 21)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("17.0.5", "outside_scope", "build_jdk_declaration", 2),
                                  ("17.0.6", "candidate", "build_jdk_declaration", 2),
                                  ("21", "candidate", "build_jdk_declaration", 2)])

    def test_yaml_block_java_versions_stop_at_next_field(self):
        for indent in ("", "  "):
            text = ('matrix:\n  java-version: # JDK matrix\n'
                    f'{indent}  - 17.0.5\n\n  # active JDKs\n{indent}  - "17.0.6"\n'
                    f"{indent}  - '21'\n  other:\n    - 25\n")
            with self.subTest(indent=indent):
                rows = list(bitbucket.declarations("build.yml", text, (17, 21, 25)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("17.0.5", "outside_scope", "build_jdk_declaration", 2),
                                  ("17.0.6", "candidate", "build_jdk_declaration", 2),
                                  ("21", "candidate", "build_jdk_declaration", 2)])

    def test_yaml_java_list_accepts_trailing_comma_but_not_empty_items(self):
        for text in ('java-version: [17.0.6, "21",]',
                     'java-version: [\n  17.0.6,\n  "21", # final version\n]'):
            with self.subTest(text=text):
                rows = list(bitbucket.declarations("build.yml", text, (17, 21)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("17.0.6", "candidate", "build_jdk_declaration", 1),
                                  ("21", "candidate", "build_jdk_declaration", 1)])
        for text in ('java-version: []', 'java-version: [17.0.6,,21]'):
            with self.subTest(text=text):
                rows = list(bitbucket.declarations("build.yml", text, (17, 21)))
                self.assertFalse(any(row["status"] == "candidate" for row in rows))

    def test_yaml_java_lists_accept_quoted_keys(self):
        for key in ('"java-version"', "'java-version'"):
            for values in ('[17.0.5, "17.0.6", 21]', '\n  - 17.0.5\n  - "17.0.6"\n  - 21'):
                with self.subTest(key=key, values=values):
                    rows = list(bitbucket.declarations("ci.yml", f"{key}: {values}", (17, 21)))
                    self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                      for row in rows],
                                     [("17.0.5", "outside_scope", "build_jdk_declaration", 1),
                                      ("17.0.6", "candidate", "build_jdk_declaration", 1),
                                      ("21", "candidate", "build_jdk_declaration", 1)])

    def test_yaml_scalar_java_version_accepts_quoted_keys_without_duplicates(self):
        for key in ('java-version', '"java-version"', "'java-version'"):
            for literal, version, status in (('"17.0.6"', "17.0.6", "candidate"),
                                             ("'21'", "21", "candidate"),
                                             ('17.0.5', "17.0.5", "outside_scope")):
                with self.subTest(key=key, literal=literal):
                    row, = bitbucket.declarations("build.yml", f"\n  {key}: {literal} # JDK", (17, 21))
                    self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                     (version, status, "build_jdk_declaration", 2))

    def test_yaml_quoted_java_environment_keys_keep_version_and_role(self):
        for text, version, status in (
                ('"JAVA_HOME": "/opt/build tools/jdk-17.0.6"', "17.0.6", "candidate"),
                ("'JAVA_VERSION': '17.0.5'", "17.0.5", "outside_scope"),
                ('"JDK_VERSION": 21', "21", "candidate")):
            with self.subTest(text=text):
                row, = bitbucket.declarations("build.yml", "env:\n  " + text, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 (version, status, "build_jdk_declaration", 2))

    def test_yaml_quoted_environment_assignments_keep_full_values(self):
        for assignment, version, status in (
                ('"JAVA_VERSION=17.0.6"', "17.0.6", "candidate"),
                ("'JDK_VERSION=21'", "21", "candidate"),
                ('"JAVA_HOME=/opt/build tools/jdk-17.0.5"', "17.0.5", "outside_scope")):
            with self.subTest(assignment=assignment):
                row, = bitbucket.declarations("compose.yml", f"environment:\n  - {assignment} # JDK", (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 (version, status, "build_jdk_declaration", 2))

    def test_gradle_logged_toolchain_calls_do_not_create_candidates(self):
        text = ('println("jvmToolchain(25)")\n'
                "println('JavaLanguageVersion.of(27)')\n"
                'println("options.release.set(25)")\n'
                'jvmToolchain(21)\n')
        for path in ("build.gradle", "build.gradle.kts"):
            with self.subTest(path=path):
                row, = bitbucket.declarations(path, text, (17, 21, 25, 27))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 ("21", "candidate", "build_jdk_declaration", 4))
        row, = bitbucket.declarations("build.gradle", 'sourceCompatibility = "21"', (17, 21))
        self.assertEqual((row["version"], row["status"]), ("21", "candidate"))

    def test_gradle_logged_inline_settings_do_not_create_candidates(self):
        for path, text, role in (
                ("build.gradle", 'println("sourceCompatibility = 25")\njava { sourceCompatibility = "21" }',
                 "bytecode_target"),
                ("build.gradle.kts", 'println("jvmTarget = JvmTarget.JVM_27")\n'
                 'compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }', "bytecode_target"),
                ("build.gradle", 'println("jvmToolchain 25")\njvmToolchain 21', "build_jdk_declaration")):
            with self.subTest(path=path, text=text):
                row, = bitbucket.declarations(path, text, (17, 21, 25, 27))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 ("21", "candidate", role, 2))

    def test_jenkins_logged_jdk_selection_does_not_create_candidate(self):
        for path in ("Jenkinsfile", "ci/Jenkinsfile.release"):
            for version, status in (("17.0.6", "candidate"), ("17.0.5", "outside_scope")):
                with self.subTest(path=path, version=version):
                    text = 'echo "Use jdk \'jdk-25\'"\n' + f"tools {{ jdk 'jdk-{version}' }}"
                    row, = bitbucket.declarations(path, text, (17, 25))
                    self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                     (version, status, "build_jdk_declaration", 2))

    def test_gradle_inline_java_version_conversion_keeps_bytecode_role(self):
        for path in ("build.gradle", "build.gradle.kts"):
            for expression, version, status in (('JavaVersion.toVersion("21")', "21", "candidate"),
                                                 ('JavaVersion.toVersion ( 21 )', "21", "candidate"),
                                                 ("JavaVersion.toVersion('1.8')", "1.8", "outside_scope")):
                with self.subTest(path=path, expression=expression):
                    row, = bitbucket.declarations(path, f"\njava {{ sourceCompatibility = {expression} }}", (17, 21))
                    self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                     (version, status, "bytecode_target", 2))

    def test_multiline_gradle_compatibility_preserves_opening_line(self):
        text = ('java {\n  sourceCompatibility =\n    JavaVersion.toVersion(\n      "21"\n    )\n'
                '  targetCompatibility =\n    JavaVersion.VERSION_11\n}\n')
        for path in ("build.gradle", "build.gradle.kts"):
            with self.subTest(path=path):
                rows = list(bitbucket.declarations(path, text, (17, 21)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("21", "candidate", "bytecode_target", 2),
                                  ("11", "outside_scope", "bytecode_target", 6)])

    def test_multiline_kotlin_jvm_target_preserves_opening_line(self):
        for expression, version, status in (
                ('jvmTarget.set(\n  JvmTarget.JVM_21\n)', "21", "candidate"),
                ('jvmTarget.set(\n  JvmTarget.fromTarget(\n    "21"\n  )\n)', "21", "candidate"),
                ('jvmTarget.set(\n  JvmTarget.JVM_1_8\n)', "1.8", "outside_scope")):
            with self.subTest(expression=expression):
                row, = bitbucket.declarations("build.gradle.kts", "\n" + expression, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 (version, status, "bytecode_target", 2))

    def test_multiline_kotlin_jvm_target_assignment_preserves_opening_line(self):
        for value, version, status in (("JvmTarget.JVM_21", "21", "candidate"),
                                         ('"21"', "21", "candidate"),
                                         ("JvmTarget.JVM_1_8", "1.8", "outside_scope")):
            with self.subTest(value=value):
                block = "kotlinOptions" if value.startswith('"') else "compilerOptions"
                text = f"{block} {{\n  jvmTarget =\n    {value}\n}}"
                row, = bitbucket.declarations("build.gradle.kts", text, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 (version, status, "bytecode_target", 2))

    def test_docker_copy_options_are_not_sources(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        cases = [
            ("--from=tools --exclude=/cache/jdk /artifacts /runtime/", "intermediate_base"),
            ('--chown=1000:1000 --from=tools ["/opt/java/openjdk/", "/runtime/"]', "bundled_jdk"),
        ]
        for arguments, role in cases:
            with self.subTest(arguments=arguments):
                row, = bitbucket.declarations("Dockerfile", base + f"COPY {arguments}")
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (1, "17.0.6", "candidate", role))

    def test_docker_copy_dot_directory_preserves_bundled_jdk_role(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        for instruction in (
                "COPY --from=tools /opt/java/openjdk/. /runtime/",
                'COPY --from=0 ["/opt/java/openjdk/./", "/runtime/"]'):
            with self.subTest(instruction=instruction):
                row, = bitbucket.declarations("Dockerfile", base + instruction)
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 ("17.0.6", "candidate", "bundled_jdk", 1))

    def test_docker_copy_versioned_jdk_directory_preserves_bundled_role(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        for instruction, role in (
                ("COPY --from=tools /opt/jdk-17.0.6/ /runtime/", "bundled_jdk"),
                ('COPY --from=0 ["/opt/openjdk_17.0.6/", "/runtime/"]', "bundled_jdk"),
                ("COPY --from=tools /opt/jdk-17.0.6/bin/java /usr/bin/java", "intermediate_base")):
            with self.subTest(instruction=instruction):
                row, = bitbucket.declarations("Dockerfile", base + instruction)
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 ("17.0.6", "candidate", role))

    def test_docker_copy_debian_openjdk_directory_preserves_bundled_role(self):
        base = "FROM openjdk:17.0.6-jdk AS tools\nFROM debian:stable\n"
        for source, role in (("/usr/lib/jvm/java-17-openjdk-amd64/", "bundled_jdk"),
                             ("/usr/lib/jvm/java-1.17.0-openjdk-amd64/.", "bundled_jdk"),
                             ("/usr/lib/jvm/java-17-openjdk-amd64/bin/java", "intermediate_base")):
            with self.subTest(source=source):
                row, = bitbucket.declarations("Dockerfile", base + f"COPY --from=tools {source} /runtime/")
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 ("17.0.6", "candidate", role))

    def test_docker_copy_quoted_paths_preserve_source_destination_boundaries(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        for arguments, role in (
                ('"/opt/java/openjdk/" "/runtime jdk/"', "bundled_jdk"),
                ("'/opt/build tools/jdk-17.0.6/' '/runtime/'", "bundled_jdk"),
                ('"/opt/artifacts/" "/runtime jdk/openjdk/"', "intermediate_base")):
            with self.subTest(arguments=arguments):
                row, = bitbucket.declarations("Dockerfile", base + f"COPY --from=tools {arguments}")
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 ("17.0.6", "candidate", role))

    def test_docker_multiline_copy_preserves_bundled_jdk_role(self):
        base = "FROM eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
        continued = "\\\n"
        for instruction, role in (
                (f"COPY --from=tools {continued}  /opt/java/openjdk/ {continued}  /runtime/", "bundled_jdk"),
                (f'COPY --from=0 {continued}# JDK\n  ["/opt/java/openjdk/", "/runtime/"]', "bundled_jdk"),
                (f"RUN echo {continued}  COPY --from=tools /opt/java/openjdk/ /runtime/", "intermediate_base")):
            with self.subTest(instruction=instruction):
                row, = bitbucket.declarations("Dockerfile", base + instruction)
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 ("17.0.6", "candidate", role, 1))

    def test_multiline_docker_from_preserves_version_role_and_opening_line(self):
        continued = "\\\n"
        text = (f"FROM --platform=linux/amd64 {continued}# build JDK\n"
                "  eclipse-temurin:17.0.6 AS tools\nFROM debian:stable\n"
                "COPY --from=tools /opt/java/openjdk/ /runtime/\n")
        row, = bitbucket.declarations("Dockerfile", text)
        self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                         ("17.0.6", "candidate", "bundled_jdk", 1))
        row, = bitbucket.declarations("Dockerfile", f"FROM {continued}  eclipse-temurin:17.0.5")
        self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                         ("17.0.5", "outside_scope", "runtime_base", 1))
        self.assertEqual(list(bitbucket.declarations("Dockerfile",
                         f"FROM debian:stable\nRUN echo {continued}  FROM eclipse-temurin:17.0.6")), [])

    def test_maven_multiline_declarations_link_to_opening_tag(self):
        pom = """<project>
  <properties>
    <jdk.version>
      17.0.6
    </jdk.version>
  </properties>
  <configuration><release>
    ${jdk.version}
  </release></configuration>
</project>"""
        rows = list(bitbucket.declarations("pom.xml", pom))
        self.assertEqual(
            [(row["line"], row["version"], row["status"], row["role"]) for row in rows],
            [(3, "17.0.6", "candidate", "build_jdk_declaration"),
             (7, "17.0.6", "candidate", "bytecode_target")],
        )

    def test_maven_comments_do_not_override_active_properties_or_shift_evidence(self):
        pom = """<project>
  <properties>
    <!-- Old setting:
         <java.version>17.0.5</java.version>
    -->
    <java.version>17.0.6</java.version>
    <!-- <jdk.version>21</jdk.version> -->
  </properties>
  <release>${java.version}</release>
</project>"""
        rows = list(bitbucket.declarations("pom.xml", pom))
        self.assertEqual(
            [(row["line"], row["version"], row["status"], row["role"]) for row in rows],
            [(6, "17.0.6", "candidate", "build_jdk_declaration"),
             (9, "17.0.6", "candidate", "bytecode_target")],
        )

    def test_yaml_image_accepts_quoted_keys(self):
        for key in ("image", "'image'", '"image"'):
            with self.subTest(key=key):
                row, = bitbucket.declarations(
                    "compose.yaml", f"services:\n  app:\n    {key}: 'eclipse-temurin:17.0.6'\n"
                )
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (3, "17.0.6", "candidate", "image_reference"))

    def test_sdkman_java_assignment_accepts_spaces_and_comments(self):
        for value, status in (("17.0.5-tem", "outside_scope"), ("17.0.6-tem", "candidate")):
            with self.subTest(value=value):
                row, = bitbucket.declarations(".sdkmanrc", f"# tools\njava = {value} # selected JDK\n")
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (2, value.removesuffix("-tem"), status, "build_jdk_declaration"))

    def test_gradle_toolchain_accepts_space_before_parenthesis(self):
        for expression in ("jvmToolchain (21)", "languageVersion.set(JavaLanguageVersion.of (21))"):
            with self.subTest(expression=expression):
                row, = bitbucket.declarations("build.gradle.kts", expression)
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (1, "21", "outside_scope", "build_jdk_declaration"))
                selected, = bitbucket.declarations("build.gradle.kts", expression, (17, 21))
                self.assertEqual(selected["status"], "candidate")

    def test_groovy_toolchain_accepts_call_without_parentheses(self):
        for expression in ("jvmToolchain 21", "languageVersion = JavaLanguageVersion.of 21"):
            with self.subTest(expression=expression):
                row, = [row for row in bitbucket.declarations("build.gradle", expression, (17, 21))
                        if row["status"] == "candidate"]
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 ("21", "candidate", "build_jdk_declaration"))

    def test_docker_env_declares_java_version(self):
        for declaration in ("ENV JAVA_VERSION=17.0.6", "ENV JAVA_VERSION 17.0.6"):
            with self.subTest(declaration=declaration):
                row, = bitbucket.declarations("Dockerfile", "FROM debian:stable\n" + declaration)
                self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                                 (2, "17.0.6", "candidate", "build_jdk_declaration"))
        self.assertFalse(list(bitbucket.declarations("Dockerfile", "RUN echo JAVA_VERSION=17.0.6")))

    def test_multiline_gradle_toolchain_preserves_opening_line(self):
        text = "java {\n  jvmToolchain(\n    21\n  )\n}"
        row, = bitbucket.declarations("build.gradle.kts", text, (17, 21))
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (2, "21", "candidate", "build_jdk_declaration"))

    def test_multiline_jenkins_jdk_preserves_declaration_line(self):
        text = "tools {\n  jdk(\n    'jdk-17.0.6'\n  )\n}"
        row, = bitbucket.declarations("Jenkinsfile", text)
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (2, "17.0.6", "candidate", "build_jdk_declaration"))

    def test_jenkins_comments_do_not_create_jdk_candidates(self):
        text = ('/*\ntools { jdk "jdk-21" }\n*/\n'
                'echo "https://nexus.invalid"; tools { /* jdk "jdk-25" */ jdk "jdk-17.0.6" } '
                '// jdk "jdk-27"\n')
        for path in ("Jenkinsfile", "ci/Jenkinsfile.release"):
            with self.subTest(path=path):
                row, = bitbucket.declarations(path, text, (17, 21, 25, 27))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 ("17.0.6", "candidate", "build_jdk_declaration", 4))

    def test_kotlin_compiler_options_jvm_target_keeps_bytecode_role(self):
        text = "compilerOptions { jvmTarget.set(JvmTarget.JVM_21) }"
        row, = bitbucket.declarations("build.gradle.kts", text, (17, 21))
        self.assertEqual((row["version"], row["status"], row["role"]),
                         ("21", "candidate", "bytecode_target"))

    def test_kotlin_jvm_target_from_string(self):
        row, = bitbucket.declarations("build.gradle.kts",
                                     'jvmTarget.set(JvmTarget.fromTarget("21"))', (17, 21))
        self.assertEqual((row["version"], row["status"], row["role"]),
                         ("21", "candidate", "bytecode_target"))

    def test_kotlin_jvm_target_enum_assignment(self):
        for expression, version, status in (
                ("jvmTarget = JvmTarget.JVM_21", "21", "candidate"),
                ("compilerOptions { jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21 }",
                 "21", "candidate"),
                ("jvmTarget = JvmTarget.JVM_1_8", "1.8", "outside_scope")):
            with self.subTest(expression=expression):
                row, = bitbucket.declarations("build.gradle.kts", expression, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                 (version, status, "bytecode_target", 1))

    def test_gradle_release_assignment_preserves_role_and_line(self):
        for path in ("build.gradle", "build.gradle.kts"):
            for text, line in (("tasks.withType(JavaCompile) { options.release = 21 }", 1),
                               ("options.release =\n    21", 1),
                               ("// options.release = 25\noptions.release = 21", 2)):
                with self.subTest(path=path, text=text):
                    row, = bitbucket.declarations(path, text, (17, 21, 25))
                    self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                     ("21", "candidate", "bytecode_target", line))

    def test_kotlin_inline_string_jvm_target(self):
        for path in ("build.gradle", "build.gradle.kts"):
            for declaration, version, status in (
                    ('kotlinOptions { jvmTarget = "21" }', "21", "candidate"),
                    ("tasks.compileKotlin { kotlinOptions.jvmTarget = '1.8' }", "1.8", "outside_scope"),
                    ('jvmTarget = "21"', "21", "candidate")):
                with self.subTest(path=path, declaration=declaration):
                    row, = bitbucket.declarations(path, "\n" + declaration, (17, 21))
                    self.assertEqual((row["version"], row["status"], row["role"], row["line"]),
                                     (version, status, "bytecode_target", 2))

    def test_gradle_comments_do_not_create_candidates_or_shift_lines(self):
        text = ('/*\njava { toolchain { languageVersion = JavaLanguageVersion.of(21) } }\n*/\n'
                'repositories { maven { url = "https://nexus.invalid/repository/public/" } }\n'
                'java { /* sourceCompatibility = 21 */ targetCompatibility = "11" } '
                '// jvmToolchain(21)\n'
                'jvmToolchain(\n  21\n)\n')
        for path in ("build.gradle", "build.gradle.kts"):
            with self.subTest(path=path):
                rows = list(bitbucket.declarations(path, text, (17, 21)))
                self.assertEqual([(row["version"], row["status"], row["role"], row["line"])
                                  for row in rows],
                                 [("11", "outside_scope", "bytecode_target", 5),
                                  ("21", "candidate", "build_jdk_declaration", 6)])

    def test_docker_env_reads_later_assignment(self):
        text = 'FROM debian:stable\nENV APP_MODE=prod JAVA_VERSION="17.0.6" OTHER=21'
        row, = bitbucket.declarations("Dockerfile", text)
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (2, "17.0.6", "candidate", "build_jdk_declaration"))

    def test_docker_env_continuation_does_not_abort_file(self):
        text = "FROM debian:stable\nENV APP_MODE=prod " + "\\" + "\n    JAVA_VERSION=17.0.6\n"
        row, = bitbucket.declarations("Dockerfile", text)
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (3, "17.0.6", "candidate", "build_jdk_declaration"))

    def test_docker_legacy_env_value_is_not_another_assignment(self):
        text = "FROM debian:stable\nENV APP_NOTE JAVA_VERSION=17.0.6"
        self.assertFalse(list(bitbucket.declarations("Dockerfile", text)))

    def test_docker_numeric_stage_copy_identifies_bundled_jdk(self):
        text = "FROM eclipse-temurin:17.0.6\nFROM debian:stable\nCOPY --from=0 /opt/java/openjdk/ /jdk/"
        row, = bitbucket.declarations("Dockerfile", text)
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (1, "17.0.6", "candidate", "bundled_jdk"))

    def test_java_home_prefers_named_jdk_over_numeric_parent_directory(self):
        for path, text, version, status in (
                ("gradle.properties", "org.gradle.java.home=/opt/8/jdk-17.0.6", "17.0.6", "candidate"),
                ("build.yml", "JAVA_HOME: /opt/21/jdk-17.0.5", "17.0.5", "outside_scope"),
                ("gradle.properties", r"org.gradle.java.home=C:\tools\8\jdk-17.0.6", "17.0.6", "candidate")):
            with self.subTest(path=path, text=text):
                row, = bitbucket.declarations(path, text, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 (version, status, "build_jdk_declaration"))

    def test_quoted_java_home_with_spaces_keeps_full_path(self):
        for path, text, version, status in (
                ("build.yml", 'JAVA_HOME: "/opt/build tools/8/jdk-17.0.6"', "17.0.6", "candidate"),
                ("build.yml", "JAVA_HOME: '/opt/build tools/21/jdk-17.0.5'", "17.0.5", "outside_scope"),
                ("Dockerfile", 'FROM debian:stable\nENV JAVA_HOME="/opt/build tools/8/jdk-17.0.6" APP_MODE=prod',
                 "17.0.6", "candidate")):
            with self.subTest(path=path, text=text):
                row, = bitbucket.declarations(path, text, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 (version, status, "build_jdk_declaration"))

    def test_macos_jdk_bundle_suffix_does_not_hide_version(self):
        for bundle, version, status in (("jdk-17.0.6.jdk", "17.0.6", "candidate"),
                                         ("jdk-17.0.5.jdk", "17.0.5", "outside_scope"),
                                         ("temurin-21.0.1.JDK", "21.0.1", "candidate")):
            with self.subTest(bundle=bundle):
                text = f"JAVA_HOME: /Library/Java/JavaVirtualMachines/{bundle}/Contents/Home"
                row, = bitbucket.declarations("build.yml", text, (17, 21))
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 (version, status, "build_jdk_declaration"))

    def test_maven_config_defines_preserve_versions_roles_and_lines(self):
        self.assertTrue(bitbucket.config_file("project/.mvn/maven.config"))
        self.assertFalse(bitbucket.config_file("docs/maven.config"))
        text = ('# -Djava.version=25\n-Djava.version=17.0.5\n'
                '-Djava.version=17.0.6\n--define=maven.compiler.release=21\n'
                '--define\njdk.version=21\n')
        rows = list(bitbucket.declarations(".mvn/maven.config", text, (17, 21, 25)))
        self.assertEqual([(row["version"], row["status"], row["role"], row["line"]) for row in rows],
                         [("17.0.5", "outside_scope", "build_jdk_declaration", 2),
                          ("17.0.6", "candidate", "build_jdk_declaration", 3),
                          ("21", "candidate", "bytecode_target", 4),
                          ("21", "candidate", "build_jdk_declaration", 6)])

    def test_gradle_java_home_property_selects_build_jdk(self):
        row, = bitbucket.declarations("gradle.properties", "org.gradle.java.home=/opt/jdk-17.0.6\n")
        self.assertEqual((row["version"], row["status"], row["role"]),
                         ("17.0.6", "candidate", "build_jdk_declaration"))

    def test_gradle_compiler_release_keeps_bytecode_role(self):
        row, = bitbucket.declarations("build.gradle.kts", "tasks.withType<JavaCompile> { options.release.set(21) }", (17, 21))
        self.assertEqual((row["version"], row["status"], row["role"]),
                         ("21", "candidate", "bytecode_target"))

    def test_gradle_multiline_release_keeps_line_and_role(self):
        text = "tasks {\n  options.release.set(\n    21\n  )\n}"
        row, = bitbucket.declarations("build.gradle.kts", text, (17, 21))
        self.assertEqual((row["line"], row["version"], row["status"], row["role"]),
                         (2, "21", "candidate", "bytecode_target"))

    def test_gradle_inline_compatibility_keeps_bytecode_role(self):
        text = "java { sourceCompatibility = JavaVersion.VERSION_21; targetCompatibility = 21 }"
        rows = list(bitbucket.declarations("build.gradle", text, (17, 21)))
        self.assertEqual([(row["version"], row["status"], row["role"]) for row in rows],
                         [("21", "candidate", "bytecode_target")] * 2)

    def test_gradle_multiple_compatibility_assignments_on_one_line(self):
        text = "sourceCompatibility = 17; targetCompatibility = 21"
        rows = list(bitbucket.declarations("build.gradle", text, (17, 21)))
        self.assertEqual([(row["version"], row["status"], row["role"]) for row in rows],
                         [("17", "unknown_version", "bytecode_target"),
                          ("21", "candidate", "bytecode_target")])

    def test_gradle_legacy_java_enum_keeps_version_and_role(self):
        for text in ("sourceCompatibility = JavaVersion.VERSION_1_8",
                     "java { targetCompatibility = JavaVersion.VERSION_1_8 }"):
            with self.subTest(text=text):
                row, = bitbucket.declarations("build.gradle", text)
                self.assertEqual((row["version"], row["status"], row["role"]),
                                 ("1.8", "outside_scope", "bytecode_target"))

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
    def test_cloud_project_key_validation_allows_unassigned_repositories(self):
        for key in ([], {}, True, 1, " "):
            with self.subTest(key=key):
                with patch.object(bitbucket, "cloud_pages", return_value=[
                        {"slug": "repo", "project": {"key": key}}]), \
                        patch.object(bitbucket, "scan_repository") as scan:
                    assets, findings, errors = bitbucket.inventory(None, bb_args(provider="cloud"))
                self.assertEqual((assets, findings, len(errors)), ([], [], 1))
                self.assertEqual(errors[0]["stage"], "list_repositories")
                self.assertIn("Invalid Bitbucket Cloud project key", errors[0]["error"])
                scan.assert_not_called()
        for project in (None, {}, {"key": None}):
            with self.subTest(project=project):
                with patch.object(bitbucket, "cloud_pages", return_value=[
                        {"slug": "repo", "project": project}]), \
                        patch.object(bitbucket, "scan_repository") as scan:
                    assets, _, errors = bitbucket.inventory(None, bb_args(provider="cloud"))
                self.assertFalse(errors)
                self.assertEqual(assets[0]["repository"], "test/repo")
                self.assertIsNone(assets[0]["project"])
                scan.assert_called_once()

    def test_cloud_invalid_mainbranch_is_reported_before_clone(self):
        for branch in ("main", [], False, {"name": []}, {"name": " "}, {"name": 1}):
            with self.subTest(branch=branch):
                with patch.object(bitbucket, "cloud_pages", return_value=[
                        {"slug": "repo", "mainbranch": branch}]), \
                        patch.object(bitbucket, "scan_repository") as scan:
                    assets, findings, errors = bitbucket.inventory(None, bb_args(provider="cloud"))
                self.assertEqual((assets, findings, len(errors)), ([], [], 1))
                self.assertEqual(errors[0]["stage"], "list_repositories")
                self.assertIn("Invalid Bitbucket Cloud mainbranch", errors[0]["error"])
                scan.assert_not_called()

    def test_malformed_repository_entries_are_reported_before_clone(self):
        for provider in ("cloud", "datacenter"):
            for repo in (None, {}, {"slug": ["repo"]}, {"slug": " "},
                         {"slug": "repo", "project": "TEST"}):
                with self.subTest(provider=provider, repo=repo):
                    catalog = "cloud_pages" if provider == "cloud" else "paged"
                    with patch.object(bitbucket, catalog, return_value=[repo]), \
                            patch.object(bitbucket, "scan_repository") as scan:
                        assets, findings, errors = bitbucket.inventory(None, bb_args(provider=provider))
                    self.assertEqual((assets, findings, len(errors)), ([], [], 1))
                    self.assertEqual(errors[0]["stage"], "list_repositories")
                    self.assertIn("Invalid Bitbucket repository entry at index 0", errors[0]["error"])
                    scan.assert_not_called()
        for project in (None, {}, {"key": []}, {"key": " "}):
            with self.subTest(project=project):
                with patch.object(bitbucket, "paged", return_value=[{"slug": "repo", "project": project}]), \
                        patch.object(bitbucket, "scan_repository") as scan:
                    assets, findings, errors = bitbucket.inventory(None, bb_args())
                self.assertEqual((assets, findings, len(errors)), ([], [], 1))
                self.assertIn("Invalid Bitbucket Data Center project key", errors[0]["error"])
                scan.assert_not_called()

    def test_cloud_rejects_malformed_pages_before_yielding_rows(self):
        for page in (None, {"values": {}}, {"values": [{"slug": "repo"}], "next": 0},
                     {"values": [{"slug": "repo"}], "next": False},
                     {"values": [{"slug": "repo"}], "next": []}):
            with self.subTest(page=page):
                class FixtureApi:
                    base = "https://api.bitbucket.org/2.0"

                    def json(self, *args):
                        return page
                with self.assertRaisesRegex(ValueError, "Invalid Bitbucket Cloud"):
                    next(bitbucket.cloud_pages(FixtureApi(), "/repositories/test"))

    def test_datacenter_rejects_malformed_pagination_before_yielding_rows(self):
        valid = {"values": [{"slug": "repo"}], "isLastPage": False, "nextPageStart": 1}
        for page in (None, {**valid, "values": {}}, {**valid, "isLastPage": "false"},
                     {**valid, "nextPageStart": "1"}, {**valid, "nextPageStart": True},
                     {**valid, "nextPageStart": -1}):
            with self.subTest(page=page):
                class FixtureApi:
                    def json(self, *args):
                        return page
                with self.assertRaisesRegex(ValueError, "Invalid Bitbucket Data Center.*start=0"):
                    next(bitbucket.paged(FixtureApi(), "/rest/api/latest/repos"))

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
    def test_empty_manifest_index_is_a_coverage_error(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        calls = []

        def run(command, *args):
            calls.append(command)
            return digest.encode() if command == "digest" else b'{"manifests":[]}'

        registry.run = run
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(nexus, "repository_catalog", return_value=[
                    {"name": "hosted", "format": "docker", "type": "hosted"}]), \
                    patch.object(nexus, "repository_assets", return_value=[
                        {"path": "v2/app/manifests/latest"}]):
                assets, findings, errors = nexus.inventory(
                    None, registry, argparse.Namespace(discovery="rest", repository=[], include_proxy=False),
                    {"hosted": "registry.example:5000"}, directory)
        self.assertEqual(calls, ["digest", "manifest"])
        self.assertEqual((len(assets), findings, len(errors)), (1, [], 1))
        self.assertEqual(assets[0]["status"], "error")
        self.assertIn("No platform manifests in image index", errors[0]["error"])
        self.assertEqual(errors[0]["image"], "app")

    def test_invalid_repository_catalog_reports_cause_before_browse(self):
        for catalog in ({"error": "denied"}, None, [None],
                        [{"name": ["hosted"], "format": "docker", "type": "hosted"}],
                        [{"name": "hosted", "format": "docker"}],
                        [{"name": " ", "format": "docker", "type": "hosted"}]):
            with self.subTest(catalog=catalog), tempfile.TemporaryDirectory() as directory:
                with patch.object(nexus, "repository_catalog", return_value=catalog), \
                        patch.object(nexus, "repository_assets") as browse:
                    assets, findings, errors = nexus.inventory(
                        None, None, argparse.Namespace(discovery="rest"), {}, directory)
                self.assertEqual((assets, findings), ([], []))
                self.assertEqual(len(errors), 1)
                self.assertEqual(errors[0]["stage"], "list_repositories")
                self.assertIn("Nexus repository catalog", errors[0]["error"])
                browse.assert_not_called()

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
            failure = ApiHttpError(404, "/service/rest/v1/repositories")

            def json(self, path):
                self_test.assertEqual(path, "/service/rest/v1/repositories")
                calls.append(path)
                if self.failure:
                    raise self.failure
                return [repository]

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
        self.assertEqual({row["path"] for row in nexus.repository_assets(api, "images")},
                         {"v2/team/image/tags/1.0", "v2/team/image/manifests/" + digest})
        self.assertIn(("coreui_Browse", "read", {"repositoryName": "images", "node": "v2"}), calls)
        with self.assertRaises(ApiHttpError):
            nexus.repository_catalog(api, "rest")
        api.failure = ApiTimeoutError("Request timed out")
        self.assertEqual(nexus.repository_catalog(api, "auto"), [repository])
        self.assertEqual(len(list(nexus.repository_assets(api, "images"))), 2)
        with self.assertRaises(ApiTimeoutError):
            nexus.repository_catalog(api, "rest")
        api.failure = RuntimeError("DNS lookup failed")
        with self.assertRaisesRegex(RuntimeError, "DNS lookup failed"):
            nexus.repository_catalog(api, "auto")
        self.assertEqual(len(list(nexus.repository_assets(api, "images"))), 2)
        for mode in ("rest", "auto"):
            with self.subTest(mode=mode):
                api.failure = None
                calls.clear()
                self.assertEqual(nexus.repository_catalog(api, mode), [repository])
                self.assertEqual(len(list(nexus.repository_assets(api, "images"))), 2)
                self.assertEqual(calls[:2], [
                    "/service/rest/v1/repositories",
                    ("coreui_Browse", "read", {"repositoryName": "images", "node": "v2"}),
                ])

    def test_path_based_routing_and_explicit_override(self):
        digest = "sha256:" + "a" * 64

        class FixtureApi:
            base = "https://nexus.example.invalid"

            def json(self, path):
                if path.endswith("/repositories"):
                    return [{"name": repo, "format": "docker", "type": "hosted"}
                            for repo in ("auto-hosted", "port-hosted")]
                raise AssertionError(path)

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
            with patch.object(nexus, "repository_assets", return_value=[
                {"path": "v2/team/demo/manifests/1.0"}
            ]):
                assets, _, errors = nexus.inventory(
                    FixtureApi(), registry, args, {"port-hosted": "https://nexus.example.invalid:18443"}, tmp
                )
        self.assertFalse(errors)
        self.assertEqual(len(assets), 2)
        self.assertEqual(registry.tags, ["nexus.example.invalid/auto-hosted/team/demo:1.0",
                                         "nexus.example.invalid:18443/team/demo:1.0"])

    def test_credentials_follow_the_resolved_registry_host(self):
        env = {"NEXUS_DOCKER_USERNAME": "reader", "NEXUS_DOCKER_PASSWORD": "fixture",
               "NEXUS_REST_USERNAME": "other", "NEXUS_REST_PASSWORD": "rest-fixture",
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

    def test_registry_reuses_rest_basic_credentials_only_on_nexus_host(self):
        env = {"NEXUS_REST_USERNAME": "reader", "NEXUS_REST_PASSWORD": "rest-fixture"}
        args = argparse.Namespace(url="https://nexus.example.invalid", crane="crane",
                                  scan_timeout=5, progress=False)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env, clear=True):
            registry = nexus.Registry(args, tmp)
            with patch("nexus_inventory.subprocess.run") as run:
                run.return_value = argparse.Namespace(returncode=0, stdout=b"result")
                host = "nexus.example.invalid:18443"
                registry.run("digest", f"{host}/demo:1.0", False)
                settings = json.loads(Path(tmp, "config.json").read_text(encoding="utf-8"))
                self.assertEqual(base64.b64decode(settings["auths"][host]["auth"]), b"reader:rest-fixture")
                self.assertEqual(run.call_args.kwargs["env"]["DOCKER_CONFIG"], tmp)
                self.assertNotIn("NEXUS_REST_PASSWORD", run.call_args.kwargs["env"])
                registry.run("digest", "other.example.invalid/demo:1.0", False)
                self.assertNotIn("DOCKER_CONFIG", run.call_args.kwargs["env"])

    def test_registry_failure_progress_includes_redacted_crane_error(self):
        args = argparse.Namespace(crane="crane", scan_timeout=5, progress=True)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as log:
            with patch.dict(os.environ, {"NEXUS_TOKEN": "fixture-secret"}, clear=True):
                registry = nexus.Registry(args, tmp)
                with patch("nexus_inventory.subprocess.run") as run:
                    run.return_value = argparse.Namespace(
                        returncode=1,
                        stderr=b"Error: GET https://registry.invalid/token?scope=private: UNAUTHORIZED fixture-secret",
                    )
                    with self.assertRaisesRegex(RuntimeError, "UNAUTHORIZED"):
                        registry.run("manifest", "registry.invalid/demo:1.0", False)
        event = json.loads(log.getvalue())
        self.assertEqual(event["event"], "registry")
        self.assertFalse(event["ok"])
        self.assertIn("UNAUTHORIZED", event["error"])
        self.assertNotIn("scope=private", event["error"])
        self.assertNotIn("fixture-secret", event["error"])

    def test_extdirect_accepts_single_rpc_response_array(self):
        api = argparse.Namespace(base="https://nexus.invalid")
        for entries in ([], [{"id": "v2/image", "leaf": False}]):
            response = {"tid": 1, "result": {"success": True, "data": entries}}
            api.read = lambda *args, **kwargs: json.dumps([response]).encode()
            self.assertEqual(nexus.extdirect_read(api, "coreui_Browse", "read", {}), entries)
        api.read = lambda *args, **kwargs: b"[]"
        with self.assertRaisesRegex(ValueError, "number of RPC responses"):
            nexus.extdirect_read(api, "coreui_Browse", "read", {})

    def test_extdirect_preserves_nested_access_error(self):
        api = argparse.Namespace(base="https://nexus.invalid")
        api.read = lambda *args, **kwargs: json.dumps({
            "result": {"success": False, "errors": {"message": "Not authorized to browse images"}}
        }).encode()
        with self.assertRaisesRegex(RuntimeError, "Not authorized to browse images"):
            nexus.extdirect_read(api, "coreui_Browse", "read", {})

    def test_extdirect_rejects_rpc_exception_even_with_success_result(self):
        api = argparse.Namespace(base="https://nexus.invalid")
        api.read = lambda *args, **kwargs: json.dumps({
            "type": "exception", "message": "Browse unavailable",
            "result": {"success": True, "data": []},
        }).encode()
        with self.assertRaisesRegex(RuntimeError, "Browse unavailable"):
            nexus.extdirect_read(api, "coreui_Browse", "read", {})

    def test_extdirect_rejects_response_for_another_transaction(self):
        api = argparse.Namespace(base="https://nexus.invalid")
        api.read = lambda *args, **kwargs: json.dumps({
            "tid": 7, "result": {"success": True, "data": []},
        }).encode()
        with self.assertRaisesRegex(ValueError, "transaction ID"):
            nexus.extdirect_read(api, "coreui_Browse", "read", {})

    def test_extdirect_rejects_response_for_another_operation(self):
        api = argparse.Namespace(base="https://nexus.invalid")
        for fields in ({"action": "coreui_Repository"}, {"method": "delete"}):
            with self.subTest(fields=fields):
                response = {"tid": 1, "result": {"success": True, "data": []}, **fields}
                api.read = lambda *args, **kwargs: json.dumps(response).encode()
                with self.assertRaisesRegex(ValueError, "another RPC operation"):
                    nexus.extdirect_read(api, "coreui_Browse", "read", {})

    def test_browse_invalid_entry_reports_repository_and_node(self):
        for entry in (None, {}, {"id": 7}, {"id": ""}):
            with self.subTest(entry=entry), patch.object(nexus, "extdirect_read", return_value=[entry]):
                with self.assertRaisesRegex(ValueError, "repository images, node v2"):
                    list(nexus.repository_assets(None, "images"))

    def test_manifest_rejects_malformed_platform_descriptor(self):
        registry = object.__new__(nexus.Registry)
        registry.run = lambda *args: (_ for _ in ()).throw(AssertionError("unexpected registry request"))
        digest = "sha256:" + "a" * 64
        with self.assertRaisesRegex(ValueError, "Invalid image platform descriptor"):
            list(registry.manifests("registry.invalid/image", digest, False, "linux/amd64"))

    def test_manifest_reports_invalid_image_config(self):
        registry = object.__new__(nexus.Registry)
        registry.run = lambda command, *args: (
            b'{"layers":[],"config":{"mediaType":"application/vnd.oci.image.config.v1+json"}}'
            if command == "manifest" else b"[]"
        )
        digest = "sha256:" + "a" * 64
        with self.assertRaisesRegex(ValueError, "Invalid image configuration"):
            list(registry.manifests("registry.invalid/image", digest, False))

    def test_manifest_reports_invalid_json_root_type(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        for value in (None, [], "layers"):
            with self.subTest(value=value):
                registry.run = lambda *args: json.dumps(value).encode()
                with self.assertRaisesRegex(ValueError, "Invalid image manifest JSON"):
                    list(registry.manifests("registry.invalid/image", digest, False))

    def test_manifest_reports_invalid_index_collection(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        for value in (None, {}, "manifests"):
            with self.subTest(value=value):
                registry.run = lambda *args: json.dumps({"manifests": value}).encode()
                with self.assertRaisesRegex(ValueError, "Invalid platform manifest list"):
                    list(registry.manifests("registry.invalid/image", digest, False))

    def test_manifest_continues_after_malformed_index_entry(self):
        registry = object.__new__(nexus.Registry)
        parent = "sha256:" + "a" * 64
        child = "sha256:" + "b" * 64
        def run(command, ref, insecure):
            if ref.endswith(parent):
                return json.dumps({"manifests": [None, {
                    "digest": child, "platform": {"os": "linux", "architecture": "amd64"},
                }]}).encode()
            return b'{"layers":[],"config":{"mediaType":"application/vnd.oci.image.config.v1+json"}}'
        registry.run = run
        errors = []
        rows = list(registry.manifests("registry.invalid/image", parent, False,
                                      on_error=lambda *args: errors.append(args)))
        self.assertEqual(rows, [(child, "linux/amd64")])
        self.assertEqual(len(errors), 1)
        self.assertIn("Invalid platform manifest descriptor", str(errors[0][2]))

    def test_manifest_continues_after_invalid_annotations(self):
        registry = object.__new__(nexus.Registry)
        parent, child = ("sha256:" + digit * 64 for digit in ("a", "b"))
        def run(command, ref, insecure):
            if ref.endswith(parent):
                return json.dumps({"manifests": [
                    {"digest": child, "annotations": ["invalid"]},
                    {"digest": child, "platform": {"os": "linux", "architecture": "amd64"}},
                ]}).encode()
            return b'{"layers":[],"config":{"mediaType":"application/vnd.oci.image.config.v1+json"}}'
        registry.run = run
        errors = []
        self.assertEqual(list(registry.manifests("registry.invalid/image", parent, False,
                                                on_error=lambda *args: errors.append(args))),
                         [(child, "linux/amd64")])
        self.assertEqual(len(errors), 1)
        self.assertIn("annotations", str(errors[0][2]))

    def test_manifest_rejects_invalid_config_descriptor(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        for config in (None, [], "application/vnd.oci.image.config.v1+json"):
            with self.subTest(config=config):
                registry.run = lambda *args: json.dumps({"layers": [], "config": config}).encode()
                with self.assertRaisesRegex(ValueError, "Invalid image config descriptor"):
                    list(registry.manifests("registry.invalid/image", digest, False))

    def test_manifest_reports_invalid_config_media_type(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        for media_type in (None, [], 1):
            with self.subTest(media_type=media_type):
                registry.run = lambda *args: json.dumps({
                    "layers": [], "config": {"mediaType": media_type},
                }).encode()
                with self.assertRaisesRegex(ValueError, "Invalid image config media type"):
                    list(registry.manifests("registry.invalid/image", digest, False))

    def test_manifest_rejects_non_string_platform_fields(self):
        registry = object.__new__(nexus.Registry)
        registry.run = lambda *args: b'{"layers":[],"config":{"mediaType":"application/vnd.oci.image.config.v1+json"}}'
        digest = "sha256:" + "a" * 64
        for key in ("architecture", "variant", "os.version"):
            with self.subTest(key=key):
                platform = {"os": "linux", "architecture": "amd64", key: ["invalid"]}
                with self.assertRaisesRegex(ValueError, "Invalid image platform fields"):
                    list(registry.manifests("registry.invalid/image", digest, False, platform))

    def test_manifest_rejects_invalid_layer_collection(self):
        registry = object.__new__(nexus.Registry)
        digest = "sha256:" + "a" * 64
        for layers in (None, {}, "layers"):
            with self.subTest(layers=layers):
                registry.run = lambda *args: json.dumps({
                    "layers": layers, "config": {"mediaType": "application/vnd.oci.image.config.v1+json"},
                }).encode()
                with self.assertRaisesRegex(ValueError, "Invalid image layer list"):
                    list(registry.manifests("registry.invalid/image", digest, False))

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

    def test_nexus_cli_prints_coverage_error_to_stderr(self):
        with tempfile.TemporaryDirectory() as output:
            argv = ["nexus_inventory.py", "--url", "https://nexus.invalid",
                    "--repository", "aa-docker-prod", "--output", output]
            with (patch("sys.argv", argv), patch.dict(os.environ, {}, clear=True),
                  patch.object(nexus, "load_env"), patch.object(nexus.shutil, "which", return_value="crane"),
                  patch.object(nexus, "repository_catalog", return_value=[]),
                  contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr):
                self.assertEqual(nexus.main(), 2)
            report = json.loads(Path(output, "inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["errors"], 1)
            with Path(output, "candidates.csv").open(encoding="utf-8-sig", newline="") as stream:
                candidates = csv.DictReader(stream)
                self.assertIn("repository", candidates.fieldnames)
                self.assertEqual(list(candidates), [])
            self.assertIn("aa-docker-prod: Repository missing from the Nexus catalog", stderr.getvalue())

    def test_nexus_masks_credentials_in_terminal_and_json_errors(self):
        with tempfile.TemporaryDirectory() as output:
            argv = ["nexus_inventory.py", "--url", "https://nexus.invalid", "--output", output]
            error = RuntimeError(
                "Denied https://reader:private@nexus.invalid/?token=query-secret fixture-secret "
                + "x" * 900 + " end of diagnostic"
            )
            with (patch("sys.argv", argv), patch.dict(os.environ, {"NEXUS_TOKEN": "fixture-secret"}, clear=True),
                  patch.object(nexus, "load_env"), patch.object(nexus.shutil, "which", return_value="crane"),
                  patch.object(nexus, "repository_catalog", side_effect=error),
                  contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr):
                self.assertEqual(nexus.main(), 2)
            report = json.loads(Path(output, "inventory.json").read_text(encoding="utf-8"))
            report_error = report["errors"][0]["error"]
        self.assertIn("list_repositories: Denied", stderr.getvalue())
        self.assertTrue(report_error.endswith("end of diagnostic"))
        for secret in ("reader:private", "query-secret", "fixture-secret"):
            self.assertNotIn(secret, stderr.getvalue())
            self.assertNotIn(secret, report_error)

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

    def test_release_reads_version_after_utf8_bom(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "rootfs.tar")
            tar_fixture(archive, {
                "runtime/release": 'JAVA_VERSION="17.0.6"\r\nJAVA_VENDOR="Fixture"\r\n'.encode("utf-8-sig"),
                "runtime/bin/java.exe": b"fixture",
            })
            finding, = nexus.java_files(archive)
        self.assertEqual(
            (finding["version"], finding["status"], finding["role"], finding["vendor"], finding["evidence"]),
            ("17.0.6", "candidate", "image_runtime", "Fixture", "/runtime/release"),
        )

    def test_release_accepts_indented_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "rootfs.tar")
            tar_fixture(archive, {
                "jdk/release": b'  JAVA_VERSION="17.0.6"  \r\n\tIMPLEMENTOR="Fixture"\r\n',
                "jdk/bin/java": b"fixture",
            })
            row, = nexus.java_files(archive)
        self.assertEqual((row["version"], row["status"], row["vendor"], row["role"]),
                         ("17.0.6", "candidate", "Fixture", "image_runtime"))

    def test_release_accepts_spacing_around_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "rootfs.tar")
            tar_fixture(archive, {
                "jdk/release": b'JAVA_VERSION = "17.0.5"\nJAVA_RUNTIME_VERSION\t=\t"17.0.6+10"\n',
                "jdk/bin/java": b"fixture",
            })
            row, = nexus.java_files(archive)
        self.assertEqual((row["version"], row["status"], row["evidence"], row["role"]),
                         ("17.0.6+10", "candidate", "/jdk/release", "image_runtime"))

    def test_deduplicate_manifest_alias_keep_untagged_digest(self):
        tagged_digest = "sha256:" + "1" * 64
        untagged_digest = "sha256:" + "2" * 64

        class NexusApi:
            def json(self, path):
                if path.endswith("/repositories"):
                    return [{"name": "hosted", "format": "docker", "type": "hosted"}]
                raise AssertionError(path)

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
            with patch.object(nexus, "repository_assets", return_value=[
                {"path": f"v2/example/service/manifests/{tagged_digest}"},
                {"path": "v2/example/service/manifests/alpha"},
                {"path": f"v2/example/service/manifests/{untagged_digest}"},
            ]):
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
            def json(self, path):
                if path.endswith("/repositories"):
                    return [{"name": "hosted", "format": "docker", "type": "hosted"}]
                raise AssertionError(path)

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
            with patch.object(nexus, "repository_assets", return_value=[
                {"path": "v2/service/manifests/latest"}
            ]):
                assets, findings, errors = nexus.inventory(
                    FixtureApi(), FixtureRegistry(), args, {"hosted": "registry.invalid"}, directory
                )
        self.assertEqual([(row["digest"], row["status"]) for row in assets],
                         [(missing, "error"), (available, "scanned")])
        self.assertEqual([(row["platform"], row["status"]) for row in findings],
                         [("linux/arm64", "candidate")])
        self.assertEqual((errors[0]["platform"], errors[0]["stage"]), ("linux/amd64", "read_platform_manifest"))


class ConsoleTests(unittest.TestCase):
    def test_start_api_rejects_non_boolean_proxy_flag(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), WebHandler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                with patch("web_app.run_job") as scan:
                    for value in ("true", "false", None, 0, 1):
                        with self.subTest(value=value):
                            request = Request(f"http://127.0.0.1:{server.server_port}/api/start/nexus",
                                              data=json.dumps({"includeProxy": value}).encode(),
                                              headers={"Content-Type": "application/json"})
                            with self.assertRaises(HTTPError) as raised:
                                urlopen(request, timeout=5)
                            with raised.exception as response:
                                self.assertEqual(response.code, 400)
                                self.assertEqual(json.load(response), {
                                    "error": "Поле includeProxy должно быть логическим значением true или false"})
                    scan.assert_not_called()
            finally:
                server.shutdown()
                thread.join()
        self.assertIn("--include-proxy", make_flags("nexus", {"includeProxy": True}))
        self.assertNotIn("--include-proxy", make_flags("nexus", {"includeProxy": False}))
        self.assertNotIn("--include-proxy", make_flags("nexus", {}))

    def test_start_api_explains_invalid_filter_types_without_starting_scan(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), WebHandler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                with patch("web_app.run_job") as scan:
                    for source, key in (("nexus", "repositories"), ("bitbucket", "projects"),
                                        ("bitbucket", "branches")):
                        with self.subTest(source=source, key=key):
                            request = Request(f"http://127.0.0.1:{server.server_port}/api/start/{source}",
                                              data=json.dumps({key: ["example"], "provider": "datacenter"}).encode(),
                                              headers={"Content-Type": "application/json"})
                            with self.assertRaises(HTTPError) as raised:
                                urlopen(request, timeout=5)
                            with raised.exception as response:
                                self.assertEqual(response.code, 400)
                                self.assertEqual(json.load(response), {
                                    "error": f"Поле {key} должно быть строкой со значениями через запятую"})
                    scan.assert_not_called()
            finally:
                server.shutdown()
                thread.join()

    def test_start_api_reports_numeric_delay_overflow_as_bad_request(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), WebHandler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                with patch("web_app.run_job") as scan:
                    request = Request(f"http://127.0.0.1:{server.server_port}/api/start/nexus",
                                      data=json.dumps({"delay": 10 ** 400}).encode(),
                                      headers={"Content-Type": "application/json"})
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(request, timeout=5)
                    with raised.exception as response:
                        self.assertEqual(response.code, 400)
                        self.assertEqual(json.load(response), {
                            "error": "Задержка должна быть числом от нуля"})
                    scan.assert_not_called()
            finally:
                server.shutdown()
                thread.join()

    def test_start_api_rejects_non_object_settings_with_clear_error(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), WebHandler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                with patch("web_app.run_job") as scan:
                    for settings in (None, [], "settings", 42):
                        with self.subTest(settings=settings):
                            request = Request(f"http://127.0.0.1:{server.server_port}/api/start/nexus",
                                              data=json.dumps(settings).encode(),
                                              headers={"Content-Type": "application/json"})
                            with self.assertRaises(HTTPError) as raised:
                                urlopen(request, timeout=5)
                            with raised.exception as response:
                                self.assertEqual(response.code, 400)
                                self.assertEqual(json.load(response), {
                                    "error": "Настройки опроса должны быть JSON-объектом"})
                    scan.assert_not_called()
            finally:
                server.shutdown()
                thread.join()

    def test_debug_logs_every_operation_without_url_parameters(self):
        job = {"id": "fixture", "started": time.monotonic(), "http": stats(), "registry": stats(),
               "messages": [], "diagnostics": [], "provider": "nexus", "debug": True}
        events = [
            {"event": "http", "operation": "/repositories?continuationToken=private", "http_status": 200,
             "target": "https://nexus.example.invalid", "ok": True, "seconds": 0.02},
            {"event": "registry", "operation": "export registry.example.invalid/demo",
             "ok": True, "seconds": 1.5},
            {"event": "registry", "operation": "manifest registry.example.invalid/demo",
             "ok": False, "seconds": 0.2, "error": "UNAUTHORIZED"},
            *[{"event": "http", "operation": "/assets", "http_status": 403, "ok": False,
               "seconds": 0.1} for _ in range(22)],
        ]
        with tempfile.TemporaryDirectory() as tmp, self.assertLogs("java4shell_detector", level="DEBUG") as log:
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
        self.assertIn("UNAUTHORIZED", output)
        self.assertTrue(any("UNAUTHORIZED" in line for line in job["diagnostics"]))
        self.assertEqual(len(job["diagnostics"]), 2)

    def test_datacenter_failure_reports_cause_and_logs_redacted_diagnostics(self):
        job = {"id": "fixture", "started": time.monotonic(), "http": stats(), "registry": stats(),
               "messages": [], "diagnostics": [], "provider": "datacenter", "debug": True}
        with tempfile.TemporaryDirectory() as tmp, self.assertLogs("java4shell_detector", level="DEBUG") as log:
            env = {"BITBUCKET_TOKEN": "fixture-secret", "BITBUCKET_ALLOW_HTTP_AUTH": "0"}
            with patch("web_app.OUTPUT", Path(tmp)), patch.dict(os.environ, env):
                run_job("bitbucket", job, ["--provider=datacenter", "--url=http://127.0.0.1:1"])
                diagnostic("bitbucket", job, "failed with fixture-secret")
        self.assertEqual(job["state"], "failed")
        self.assertTrue(any("Authenticated REST requests require HTTPS" in line for line in job["diagnostics"]))
        self.assertIn("exit=2", "\n".join(log.output))
        self.assertNotIn("fixture-secret", "\n".join(log.output))

    def test_nexus_results_include_successful_images_without_java(self):
        assets = [{"repository": "images", "image": f"tools/no-java-{index:02}", "reference": "latest",
                   "status": "scanned", "findings": 0} for index in range(11)]
        assets.append({**assets[0], "platform": "linux/arm64"})
        assets.extend([
            {"repository": "images", "image": "with-java", "reference": "latest", "status": "scanned", "findings": 1},
            {"repository": "images", "image": "partial", "reference": "latest", "status": "scanned", "findings": 0},
            {"repository": "images", "image": "partial", "reference": "latest", "status": "error"},
        ])
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            output = Path(tmp)
            write_reports(output / "nexus" / "run", {"source": "nexus", "url": "https://nexus.invalid"},
                          assets, [{"repository": "images", "image": "with-java", "reference": "latest", "status": "candidate"}], [])
            with patch("web_app.OUTPUT", output):
                first = results_page("nexus", 1, False)
                second = results_page("nexus", 2, False)
                candidates = results_page("nexus", 1, True)
        self.assertEqual((first["total"], first["pages"], len(first["items"]), len(second["items"])), (12, 2, 10, 2))
        empty = [item for item in first["items"] + second["items"] if item.get("noJavaFound")]
        self.assertEqual(len(empty), 11)
        self.assertTrue(all(item["findings"] == [] and item["url"].startswith("https://nexus.invalid/#browse/") for item in empty))
        self.assertEqual(candidates["total"], 1)
        self.assertEqual(candidates["items"][0]["title"], "with-java:latest")

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

    def test_http_stats_preserve_method_and_reset_status_on_transport_error(self):
        row = stats()
        update_stats(row, {"seconds": 0.05, "ok": True, "method": "GET",
                           "operation": "/service/rest/v1/repositories", "http_status": 200})
        update_stats(row, {"seconds": 0.1, "ok": False, "method": "POST",
                           "operation": "/service/extdirect"})
        self.assertEqual((row["method"], row["operation"], row["http_status"], row["errors"]),
                         ("POST", "/service/extdirect", None, 1))

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
