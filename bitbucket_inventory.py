"""Inventory Java declarations in Bitbucket Data Center at pinned commits."""
import argparse
import base64
import fnmatch
import json
import math
import os
import re
import shutil
import shlex
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from inventory_common import (
    Api, DEFAULT_JAVA_MAJORS, JAVA4SHELL_MAJORS, LEGACY_VERSION,
    classify, java4shell_result, java_major, load_env, parse_java_majors, report_progress, write_reports,
)

API_ROOT = "/rest/api/latest"
ERRORS = (RuntimeError, ValueError, KeyError, TypeError, OSError)
JAVA = r"(?:openjdk|temurin|(?:amazon)?corretto|zulu|sapmachine|liberica|semeru|graalvm|oraclejdk|oracle-jdk|jdk|jre|java|jetbrains/runtime)"
JAVA_IMAGE = re.compile(rf"(?:^|[/_.-]){JAVA}(?=[:/_.@\d-]|$)", re.I)
TEMURIN_IMAGE = re.compile(r"(?:^|/)eclipse-temurin(?=[:@]|$)", re.I)
COPY_OPTIONS = re.compile(r"^\s*COPY\s+((?:--\S+\s+)+)(.+)$", re.I)
JDK_DIRECTORY = re.compile(r"[^\r\n]*/(?:jdk|openjdk|jre)/?", re.I)
JAVA_TAG_VERSION = re.compile(rf"(?:^|[_.-]){JAVA}[_.-]?(?=\d)", re.I)
VARIABLE = re.compile(r"\$\{([\w.-]+)\}|\$([A-Za-z_]\w*)")
SETTING = re.compile(
    r"^\s*(?:-\s*)?(?P<key>java[._-]?(?:version|home)|jdk[._-]?(?:version|home)|"
    r"maven\.compiler\.(?:release|source|target)|sourceCompatibility|targetCompatibility|"
    r"languageVersion|jvmTarget|jdkVersion|java-version|JAVA_TOOLCHAIN_VERSION)"
    r"(?:\s*[:=]\s*|\s+)(?P<value>[^\s<#]+|.+)", re.I
)
XML = re.compile(
    r"<(?P<key>java\.version|jdk\.version|maven\.compiler\.(?:release|source|target)|"
    r"release|source|target|jdk)>\s*(?P<value>[^<]+?)\s*</(?P=key)>", re.I
)
ARG = re.compile(r"^\s*ARG\s+(\w+)(?:\s*=\s*(\S+))?", re.I)
FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)
IMAGE = re.compile(r"""^\s*(?:-\s*)?(?:image|"image"|'image')\s*:\s*['"]?([^\s'"]+)""", re.I)
GRADLE_TOOLCHAIN = re.compile(r"\b(?:JavaLanguageVersion\.of|jvmToolchain)\s*\(\s*([^(),]+)\s*\)")
GRADLE_GROOVY_TOOLCHAIN = re.compile(r"\b(?:JavaLanguageVersion\.of|jvmToolchain)\s+(\d+)\b")
GRADLE_JVM_TARGET = re.compile(r"\bjvmTarget\.set\(\s*(?:[\w.]+\.)?JVM_(\d+)(?:_(\d+))?\s*\)")
GRADLE_JVM_TARGET_STRING = re.compile(r"""\bjvmTarget\.set\(\s*(?:[\w.]+\.)?JvmTarget\.fromTarget\(\s*['"]([\d.]+)['"]\s*\)\s*\)""")
JENKINS_JDK = re.compile(r"\bjdk\s*\(?\s*['\"]([^'\"]+)['\"]")
NUMERIC_VALUE = re.compile(r"(?:^|[\s:'\"(/_-])(?:1\.8|\d+)(?=$|[.\s+'\")_/-])")


def paged(api, path, **params):
    start = 0
    seen = set()
    while start not in seen:
        seen.add(start)
        page = api.json(path, {**params, "start": start, "limit": 200})
        yield from page["values"]
        if page["isLastPage"]:
            return
        start = page["nextPageStart"]
    raise ValueError("Repeated Bitbucket page cursor")


def config_file(path):
    name = PurePosixPath(path).name.lower()
    return (name.startswith(("dockerfile", "containerfile", "jenkinsfile"))
            or name.endswith((".dockerfile", ".containerfile", ".yaml", ".yml", ".gradle", ".gradle.kts"))
            or name in {"pom.xml", "gradle.properties", ".java-version", ".tool-versions",
                        ".sdkmanrc", ".gitlab-ci.yml"})


def substitute(value, variables):
    for _ in range(10):
        updated = VARIABLE.sub(lambda m: variables.get(m[1] or m[2], m[0]), value)
        if updated == value:
            break
        value = updated
    return value


def safe_version(value):
    return value if re.fullmatch(r"[A-Za-z0-9._+\-]{1,100}", value) else ""


def version_value(value, java_majors):
    cleaned = value.strip().strip("'\"")
    if VARIABLE.search(cleaned) or "{{" in cleaned:
        return "", "unknown_version"
    if LEGACY_VERSION.search(cleaned):
        return classify(cleaned, java_majors)
    compatibility = re.search(r"\bVERSION_(\d+)\b", cleaned)
    if compatibility:
        return classify(compatibility[1], java_majors)
    if re.match(r"^\d+(?:$|[.+_-])", cleaned) or NUMERIC_VALUE.search(cleaned):
        return classify(cleaned, java_majors)
    return "", "unknown_version"


def copied_jdk_stages(lines):
    stages = set()
    for line in lines:
        copy = COPY_OPTIONS.match(line)
        if not copy:
            continue
        options, arguments = copy.groups()
        stage = next((option[7:] for option in options.split() if option.lower().startswith("--from=")), "")
        if not stage:
            continue
        if arguments.startswith("["):
            try:
                paths = json.loads(arguments)
            except ValueError:
                continue
        else:
            paths = arguments.split()
        if len(paths) < 2 or not all(isinstance(path, str) and path for path in paths):
            continue
        if any(JDK_DIRECTORY.fullmatch(source) for source in paths[:-1]):
            stages.add(stage.lower())
    return stages


def declarations(path, text, java_majors=DEFAULT_JAVA_MAJORS):
    name = PurePosixPath(path).name.lower()
    if name == "pom.xml":
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"<!--.*?(?:-->|\Z)", lambda comment: "\n" * comment[0].count("\n"), text, flags=re.S)
    lines = text.splitlines()
    dockerfile = name.startswith(("dockerfile", "containerfile")) or name.endswith(
        (".dockerfile", ".containerfile")
    )
    stages = [number for number, line in enumerate(lines, 1) if FROM.match(line)] if dockerfile else []
    copied_jdks = copied_jdk_stages(lines[stages[-1]:]) if stages else set()
    variables = {}
    xml_declarations = {}
    gradle_declarations = {}
    jenkins_declarations = {}
    if name.startswith("jenkinsfile"):
        for match in JENKINS_JDK.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            jenkins_declarations.setdefault(line_number, []).append(("jdk", match[1]))
    if name.endswith((".gradle", ".gradle.kts")):
        for match in GRADLE_TOOLCHAIN.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            gradle_declarations.setdefault(line_number, []).append(("toolchain", match[1]))
    if name == "pom.xml":
        for block in re.findall(r"<properties>(.*?)</properties>", text, re.S):
            for key, value in re.findall(r"<([\w.-]+)>\s*([^<]+?)\s*</\1>", block):
                if key in variables and variables[key] != value:
                    variables[key] = "${" + key + "}"
                else:
                    variables[key] = value
        line_number = 1
        previous_offset = 0
        for match in XML.finditer(text):
            line_number += text.count("\n", previous_offset, match.start())
            previous_offset = match.start()
            xml_declarations.setdefault(line_number, []).append((match["key"], match["value"]))

    def finding(line, role, evidence, value, image=False):
        resolved = substitute(value, variables)
        vendor = ""
        distribution = ""
        if image:
            ref = resolved.split("@", 1)[0]
            leaf = ref.rsplit("/", 1)[-1]
            tag = leaf.partition(":")[2]
            hint = JAVA_TAG_VERSION.search(tag)
            inferred = tag[hint.end():] if hint else tag
            version, status = classify(inferred, java_majors) if not VARIABLE.search(ref) and "{{" not in ref else ("", "unknown_version")
            if "graalvm" in ref.lower():
                distribution = "GraalVM"
            elif TEMURIN_IMAGE.search(ref):
                vendor = "Eclipse Adoptium"
            elif re.search(r"(?:^|/)(?:oraclejdk|oracle-jdk|oracle/jdk|oracle/serverjre)(?=[:/]|$)", ref, re.I) or ref.lower().startswith("container-registry.oracle.com/java/"):
                vendor = "Oracle"
        else:
            version, status = version_value(resolved, java_majors)
        return {"role": role, "evidence": f"{path} ({evidence})", "line": line,
                "version": version, "declared_version": safe_version(version), "status": status,
                "vendor": vendor, "distribution": distribution}

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        arg = ARG.match(line) if dockerfile and stages and number < stages[0] else None
        if arg and arg[2]:
            variables[arg[1]] = arg[2].strip("'\"")
        stage = FROM.match(line) if dockerfile else None
        image = IMAGE.match(line) if name.endswith((".yaml", ".yml")) else None
        if stage or image:
            value = (stage or image)[1]
            resolved = substitute(value, variables)
            if JAVA_IMAGE.search(resolved) or JAVA_IMAGE.search(value) or VARIABLE.search(value) or "{{" in value:
                role = ("runtime_base" if number == stages[-1] else "intermediate_base") if stage else "image_reference"
                if stage and stage[2] and stage[2].lower() in copied_jdks:
                    role = "bundled_jdk"
                yield finding(number, role, "FROM" if stage else "image", value, image=True)
            continue
        matches = xml_declarations.pop(number, [])
        setting_line = re.sub(r"^\s*ENV\s+", "", line, flags=re.I) if dockerfile else line
        setting = SETTING.match(setting_line)
        if setting:
            matches.append((setting["key"], setting["value"]))
        if dockerfile and setting_line != line:
            assignments = shlex.split(setting_line.rstrip().removesuffix("\\"), comments=True)
            if assignments and "=" in assignments[0]:
                for assignment in assignments[1:]:
                    if "=" in assignment and (extra_setting := SETTING.match(assignment)):
                        matches.append((extra_setting["key"], extra_setting["value"]))
        matches.extend(gradle_declarations.pop(number, []))
        if name.endswith((".gradle", ".gradle.kts")):
            matches.extend(("jvmTarget", ".".join(part for part in match.groups() if part))
                           for match in GRADLE_JVM_TARGET.finditer(line))
            matches.extend(("jvmTarget", match[1]) for match in GRADLE_JVM_TARGET_STRING.finditer(line))
        if name.endswith(".gradle"):
            matches.extend(("toolchain", match[1]) for match in GRADLE_GROOVY_TOOLCHAIN.finditer(line))
        matches.extend(jenkins_declarations.pop(number, []))
        if name == ".java-version":
            matches.append(("java-version", stripped))
        if name == ".tool-versions":
            tool, *versions = stripped.partition("#")[0].split()
            if tool == "java":
                matches.extend(("java-version", version) for version in versions)
        if name == ".sdkmanrc":
            sdkman = re.match(r"java\s*=\s*([^#]+)", stripped)
            if sdkman:
                matches.append(("java-version", sdkman[1].strip()))
        for key, value in matches:
            if key.lower() in {"release", "source", "target"} and not re.match(r"^\s*(?:\d|\$\{)", value):
                continue
            target = key.lower() in {"release", "source", "target", "sourcecompatibility",
                                     "targetcompatibility", "jvmtarget"} or key.startswith("maven.compiler.")
            role = "bytecode_target" if target else "build_jdk_declaration"
            yield finding(number, role, key, value)


def cloud_pages(api, path):
    seen = set()
    while path and path not in seen:
        seen.add(path)
        page = api.json(path)
        yield from page["values"]
        following = page.get("next")
        if following and not following.startswith(api.base + "/"):
            raise ValueError("Cloud pagination attempted to leave the configured API")
        path = following[len(api.base):] if following else None
    if path:
        raise ValueError("Repeated Bitbucket Cloud page")


def git_run(args, directory, *command, clone=False):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GIT_", "NEXUS_", "BITBUCKET_"))}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    if clone and args.git_auth:
        # Pass credentials in the command environment, never in the URL or argv.
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
                   GIT_CONFIG_VALUE_0="Authorization: " + args.git_auth)
    started = time.monotonic()
    ok = False
    try:
        result = subprocess.run(
            ["git", "-c", "http.followRedirects=false", "-C", str(directory), *command],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=args.git_timeout, check=False,
        )
        ok = result.returncode == 0
        if not ok:
            detail = result.stderr.decode(errors="replace").strip()
            for secret in (args.git_auth, os.getenv("BITBUCKET_TOKEN"), os.getenv("BITBUCKET_CLOUD_TOKEN")):
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            raise RuntimeError(f"git {command[0]} exited {result.returncode}: {detail[:500]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git {command[0]} timed out after {args.git_timeout:g} s") from None
    finally:
        if clone:
            report_progress(args.progress, "git", time.monotonic() - started, ok, command[-2])


def git_refs(args, directory, default):
    branch = git_run(args, directory, "symbolic-ref", "--short", "HEAD").decode().strip()
    output = git_run(args, directory, "for-each-ref", "--format=%(refname:strip=3)%00%(objectname)",
                     "refs/remotes/origin/")
    branches = dict(line.split("\0", 1) for line in output.decode().splitlines())
    default = default or branch
    selected = [name for name in branches if name != "HEAD" and (
        name == default or any(fnmatch.fnmatchcase(name, pattern) for pattern in args.branch)
    )]
    return [(name, branches[name]) for name in sorted(selected, key=lambda name: (name != default, name))]


def scan_tree(args, directory, asset, findings, errors, checked_files):
    entries = git_run(args, directory, "ls-tree", "-r", "-l", "-z", asset["commit"]).split(b"\0")
    for entry in filter(None, entries):
        metadata, _, name = entry.partition(b"\t")
        mode, kind, object_id, size = metadata.split()
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            continue
        file = name.decode("utf-8", errors="replace")
        if not config_file(file):
            continue
        revision = (name, object_id)
        if revision in checked_files:
            continue
        try:
            if int(size) > args.max_file_bytes:
                raise ValueError(f"File exceeds {args.max_file_bytes} bytes")
            text = git_run(args, directory, "cat-file", "blob", object_id.decode()).decode("utf-8-sig")
            for row in declarations(file, text, args.java_majors):
                if args.profile == "java4shell":
                    row["status"], row["policy_reason"] = java4shell_result(row)
                if row["status"] == "candidate":
                    row["java_major"] = java_major(row["version"])
                findings.append({**asset, **row, "file": file})
                if row["status"] == "candidate":
                    return True
            checked_files.add(revision)
        except ERRORS as exc:
            errors.append({**asset, "file": file, "error": str(exc)})
    return False


def scan_repository(args, url, default, asset, findings, errors):
    errors_before, findings_before = len(errors), len(findings)
    candidate = False
    try:
        with tempfile.TemporaryDirectory(prefix="java4shell-git-") as temporary:
            root = Path(temporary)
            command = ["clone", "--quiet", "--depth", "1", "--no-checkout", "--no-tags",
                       "--no-single-branch" if args.branch else "--single-branch"]
            if default:
                command.extend(["--branch", default])
            git_run(args, root, *command, "--", url, "repository", clone=True)
            directory = root / "repository"
            refs = git_refs(args, directory, default)
            checked = set()
            checked_files = set()
            for branch, commit in refs:
                if commit in checked:
                    continue
                checked.add(commit)
                asset.update(branch=branch, commit=commit)
                candidate = scan_tree(args, directory, asset, findings, errors, checked_files)
                if candidate:
                    break
            if not refs:
                asset["status"] = "empty_repository"
    except ERRORS as exc:
        errors.append({**asset, "stage": "git", "error": str(exc)})
    asset.update(
        status="partial" if len(errors) > errors_before else asset.get("status", "scanned"),
        findings=len(findings) - findings_before, candidate=candidate,
    )


def inventory(api, args):
    assets, findings, errors = [], [], []
    seen_repositories = set()
    cloud = args.provider == "cloud"
    try:
        if cloud:
            route = "/repositories/" + quote(args.workspace, safe="")
            catalog = cloud_pages(api, route + "?pagelen=100")
        else:
            catalog = paged(api, API_ROOT + "/repos")
        for repo in catalog:
            project = (repo.get("project") or {}).get("key")
            slug = repo["slug"]
            if args.project and project not in args.project:
                continue
            owner = args.workspace if cloud else project
            repository = f"{owner}/{slug}"
            if repository in seen_repositories:
                continue
            seen_repositories.add(repository)
            asset = {"source": "bitbucket_cloud" if cloud else "bitbucket",
                     "repository": repository, "project": project}
            assets.append(asset)
            safe_owner = quote(owner if cloud else owner.lower(), safe="")
            safe_slug = quote(slug, safe="")
            if cloud:
                url = f"https://bitbucket.org/{safe_owner}/{safe_slug}.git"
                default = (repo.get("mainbranch") or {}).get("name")
            else:
                url = f"{api.base}/scm/{safe_owner}/{safe_slug}.git"
                default = None
            scan_repository(args, url, default, asset, findings, errors)
    except ERRORS as exc:
        errors.append({"stage": "list_repositories", "error": str(exc)})
    return assets, findings, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url")
    parser.add_argument("--provider", choices=("cloud", "datacenter"))
    parser.add_argument("--workspace")
    parser.add_argument("--profile", choices=("inventory", "java4shell"), default="inventory")
    parser.add_argument("--java-majors", type=parse_java_majors, default=DEFAULT_JAVA_MAJORS,
                        help="Comma-separated Java major versions, e.g. 17,21,25,27 (default: 17)")
    parser.add_argument("--output", default="reports/bitbucket")
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument("--branch", action="append", default=[],
                        help="Additional branch glob; repeat or use '*' for all branches")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--git-timeout", type=float, default=300)
    parser.add_argument("--delay", type=float, default=0.1, help="Seconds between REST GET requests")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args()
    if args.profile == "java4shell":
        args.java_majors = JAVA4SHELL_MAJORS
    if (not all(math.isfinite(value) and value > 0 for value in (args.timeout, args.git_timeout)) or args.max_file_bytes <= 0
            or not math.isfinite(args.delay) or args.delay < 0):
        parser.error("Use a positive timeout and file size, and a non-negative delay")
    try:
        load_env()
        if not shutil.which("git"):
            raise ValueError("git executable not found")
        args.provider = args.provider or os.getenv("BITBUCKET_PROVIDER", "datacenter")
        if args.provider not in {"cloud", "datacenter"}:
            raise ValueError("BITBUCKET_PROVIDER must be cloud or datacenter")
        args.workspace = args.workspace or os.getenv("BITBUCKET_CLOUD_WORKSPACE", "")
        if args.provider == "cloud":
            args.url = args.url or "https://api.bitbucket.org/2.0"
            if not args.workspace:
                raise ValueError("Set BITBUCKET_CLOUD_WORKSPACE or --workspace")
            token = os.getenv("BITBUCKET_CLOUD_TOKEN")
            email = os.getenv("BITBUCKET_CLOUD_EMAIL")
            if email and token:
                authorization = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()
            else:
                authorization = f"Bearer {token}" if token else None
        else:
            args.url = args.url or os.getenv("BITBUCKET_URL", "")
            token = os.getenv("BITBUCKET_TOKEN")
            authorization = f"Bearer {token}" if token else None
        args.git_auth = authorization
        if args.provider == "cloud" and token:
            git_user = "x-bitbucket-api-token-auth" if email else "x-token-auth"
            args.git_auth = "Basic " + base64.b64encode(f"{git_user}:{token}".encode()).decode()
        api = Api(args.url, authorization, args.timeout, args.delay, args.progress,
                  allow_http_auth=os.getenv("BITBUCKET_ALLOW_HTTP_AUTH") == "1" and args.provider == "datacenter")
    except ValueError as exc:
        parser.error(str(exc))
    return write_reports(args.output, {"source": "bitbucket", "provider": args.provider,
                                       "workspace": args.workspace if args.provider == "cloud" else None, "url": args.url,
                                       "projects": args.project, "additional_branches": args.branch,
                                       "request_delay_seconds": args.delay, "java_majors": args.java_majors,
                                       "profile": args.profile},
                         *inventory(api, args))


if __name__ == "__main__":
    raise SystemExit(main())
