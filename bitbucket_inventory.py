"""Inventory Java declarations in Bitbucket Data Center at pinned commits."""
import argparse
import base64
import fnmatch
import math
import os
import re
from pathlib import PurePosixPath
from urllib.parse import quote

from inventory_common import Api, DEFAULT_JAVA_MAJORS, classify, load_env, parse_java_majors, write_reports

API_ROOT = "/rest/api/latest"
ERRORS = (RuntimeError, ValueError, KeyError, TypeError, OSError)
JAVA = r"(?:openjdk|temurin|(?:amazon)?corretto|zulu|sapmachine|liberica|semeru|graalvm|oraclejdk|oracle-jdk|jdk|jre|java|jetbrains/runtime)"
JAVA_IMAGE = re.compile(rf"(?:^|[/_.-]){JAVA}(?=[:/_.@\d-]|$)", re.I)
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
IMAGE = re.compile(r"^\s*(?:-\s*)?image\s*:\s*['\"]?([^\s'\"]+)", re.I)
GRADLE_TOOLCHAIN = re.compile(r"\b(?:JavaLanguageVersion\.of|jvmToolchain)\(\s*([^(),]+)\s*\)")
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
    if re.search(r"(?<!\d)1\.8(?:[._]|$)", cleaned):
        return classify(cleaned, java_majors)
    compatibility = re.search(r"\bVERSION_(\d+)\b", cleaned)
    if compatibility:
        return classify(compatibility[1], java_majors)
    if re.match(r"^\d+(?:$|[.+_-])", cleaned) or NUMERIC_VALUE.search(cleaned):
        return classify(cleaned, java_majors)
    return "", "unknown_version"


def declarations(path, text, java_majors=DEFAULT_JAVA_MAJORS):
    name = PurePosixPath(path).name.lower()
    lines = text.splitlines()
    dockerfile = name.startswith(("dockerfile", "containerfile")) or name.endswith(
        (".dockerfile", ".containerfile")
    )
    stages = [number for number, line in enumerate(lines, 1) if FROM.match(line)] if dockerfile else []
    variables = {}
    if name == "pom.xml":
        for block in re.findall(r"<properties>(.*?)</properties>", text, re.S):
            for key, value in re.findall(r"<([\w.-]+)>\s*([^<]+?)\s*</\1>", block):
                if key in variables and variables[key] != value:
                    variables[key] = "${" + key + "}"
                else:
                    variables[key] = value

    def finding(line, role, evidence, value, image=False):
        resolved = substitute(value, variables)
        if image:
            ref = resolved.split("@", 1)[0]
            leaf = ref.rsplit("/", 1)[-1]
            tag = leaf.partition(":")[2]
            hint = JAVA_TAG_VERSION.search(tag)
            inferred = tag[hint.end():] if hint else tag
            version, status = classify(inferred, java_majors) if not VARIABLE.search(ref) and "{{" not in ref else ("", "unknown_version")
        else:
            version, status = version_value(resolved, java_majors)
        return {"role": role, "evidence": f"{path} ({evidence})", "line": line,
                "version": version, "declared_version": safe_version(version), "status": status}

    in_xml_comment = False
    for number, line in enumerate(lines, 1):
        if name == "pom.xml":
            if in_xml_comment:
                if "-->" not in line:
                    continue
                line = line.split("-->", 1)[1]
                in_xml_comment = False
            line = re.sub(r"<!--.*?-->", "", line)
            if "<!--" in line:
                line = line.split("<!--", 1)[0]
                in_xml_comment = True
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
                yield finding(number, role, "FROM" if stage else "image", value, image=True)
            continue
        matches = [(m["key"], m["value"]) for m in XML.finditer(line)] if name == "pom.xml" else []
        setting = SETTING.match(line)
        if setting:
            matches.append((setting["key"], setting["value"]))
        if name.endswith((".gradle", ".gradle.kts")):
            matches.extend(("toolchain", match[1]) for match in GRADLE_TOOLCHAIN.finditer(line))
        if name.startswith("jenkinsfile"):
            matches.extend(("jdk", match[1]) for match in JENKINS_JDK.finditer(line))
        if name == ".java-version":
            matches.append(("java-version", stripped))
        if name == ".tool-versions" and stripped.startswith("java "):
            matches.append(("java-version", stripped.split()[1]))
        if name == ".sdkmanrc" and stripped.startswith("java="):
            matches.append(("java-version", stripped.partition("=")[2]))
        for key, value in matches:
            if key.lower() in {"release", "source", "target"} and not re.match(r"^\s*(?:\d|\$\{)", value):
                continue
            target = key.lower() in {"release", "source", "target", "sourcecompatibility",
                                     "targetcompatibility", "jvmtarget"} or key.startswith("maven.compiler.")
            role = "bytecode_target" if target else "build_jdk_declaration"
            yield finding(number, role, key, value)


def inventory(api, args):
    assets, findings, errors = [], [], []
    try:
        for repo in paged(api, API_ROOT + "/repos"):
            project, slug = repo["project"]["key"], repo["slug"]
            if args.project and project not in args.project:
                continue
            repository = f"{project}/{slug}"
            base = f"{API_ROOT}/projects/{quote(project, safe='')}/repos/{quote(slug, safe='')}"
            try:
                available = list(paged(api, base + "/branches"))
                default_id = None
                if available and not any(branch.get("default") or branch.get("isDefault") for branch in available):
                    default_id = api.json(base + "/default-branch")["id"]
                branches = [
                    branch for branch in available
                    if branch.get("default") or branch.get("isDefault")
                    or (default_id and branch["id"] == default_id) or any(
                        fnmatch.fnmatchcase(branch["displayId"], pattern) for pattern in args.branch
                    )
                ]
                if not branches:
                    assets.append({"repository": repository,
                                   "status": "no_selected_branches" if available else "empty_repository"})
                commits = {}
                for branch in branches:
                    commit = branch["latestCommit"]
                    refs = commits.setdefault(commit, [])
                    refs.append(branch["displayId"])
                for commit, refs in commits.items():
                    asset = {"source": "bitbucket", "repository": repository,
                             "project": project, "branch": ", ".join(refs), "commit": commit}
                    assets.append(asset)
                    scan_commit(api, args, asset, findings, errors, cloud=False, base=base)
            except ERRORS as exc:
                errors.append({"repository": repository, "error": str(exc)})
    except ERRORS as exc:
        errors.append({"stage": "list_repositories", "error": str(exc)})
    return assets, findings, errors


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


def cloud_files(api, root):
    pending = [""]
    while pending:
        folder = pending.pop()
        for entry in cloud_pages(api, root + quote(folder) + "?pagelen=100"):
            path = entry["path"]
            if entry["type"] == "commit_directory":
                pending.append(path + "/")
            elif entry["type"] == "commit_file":
                yield path


def cloud_inventory(api, args):
    assets, findings, errors = [], [], []
    repos = "/repositories/" + quote(args.workspace, safe="")
    try:
        for repo in cloud_pages(api, repos + "?pagelen=100"):
            project = (repo.get("project") or {}).get("key")
            slug = repo["slug"]
            repository = f"{args.workspace}/{slug}"
            base = repos + "/" + quote(slug, safe="")
            try:
                if not project and args.project:
                    project = (api.json(base).get("project") or {}).get("key")
                if args.project and project not in args.project:
                    continue
                default = repo.get("mainbranch")
                if not default:
                    assets.append({"repository": repository, "project": project,
                                   "status": "empty_repository"})
                    continue
                default_name = default["name"]
                if args.branch:
                    branches = [branch for branch in cloud_pages(api, base + "/refs/branches?pagelen=100")
                                if branch["name"] == default_name or any(
                                    fnmatch.fnmatchcase(branch["name"], pattern) for pattern in args.branch)]
                else:
                    branches = [api.json(base + "/refs/branches/" + quote(default_name, safe=""))]
                commits = {}
                for branch in branches:
                    commits.setdefault(branch["target"]["hash"], []).append(branch["name"])
                for commit, refs in commits.items():
                    asset = {"source": "bitbucket_cloud", "repository": repository, "project": project,
                             "branch": ", ".join(refs), "commit": commit}
                    assets.append(asset)
                    scan_commit(api, args, asset, findings, errors, cloud=True, base=base)
            except ERRORS as exc:
                errors.append({"repository": repository, "error": str(exc)})
    except ERRORS as exc:
        errors.append({"stage": "list_repositories", "error": str(exc)})
    return assets, findings, errors


def scan_commit(api, args, asset, findings, errors, *, cloud, base):
    commit = asset["commit"]
    root = base + "/src/" + quote(commit, safe="") + "/" if cloud else base + "/raw/"
    params = None if cloud else {"at": commit}
    paths = cloud_files(api, root) if cloud else paged(api, base + "/files", at=commit)
    errors_before = len(errors)
    count_before = len(findings)
    try:
        for path in paths:
            if not config_file(path):
                continue
            try:
                data = api.read(root + quote(path), params, args.max_file_bytes, accept="*/*")
                findings.extend({**asset, **row} for row in declarations(
                    path, data.decode("utf-8-sig"), args.java_majors
                ))
            except ERRORS as exc:
                errors.append({**asset, "file": path, "error": str(exc)})
    except ERRORS as exc:
        errors.append({**asset, "error": str(exc)})
    asset.update(status="partial" if len(errors) > errors_before else "scanned",
                 findings=len(findings) - count_before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url")
    parser.add_argument("--provider", choices=("cloud", "datacenter"))
    parser.add_argument("--workspace")
    parser.add_argument("--java-majors", type=parse_java_majors, default=DEFAULT_JAVA_MAJORS,
                        help="Comma-separated Java major versions, e.g. 17,21,25,27 (default: 17)")
    parser.add_argument("--output", default="reports/bitbucket")
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument("--branch", action="append", default=[],
                        help="Additional branch glob; repeat or use '*' for all branches")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--delay", type=float, default=0.1, help="Seconds between REST GET requests")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args()
    if (not math.isfinite(args.timeout) or args.timeout <= 0 or args.max_file_bytes <= 0
            or not math.isfinite(args.delay) or args.delay < 0):
        parser.error("Use a positive timeout and file size, and a non-negative delay")
    try:
        load_env()
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
        api = Api(args.url, authorization, args.timeout, args.delay, args.progress,
                  allow_http_auth=os.getenv("BITBUCKET_ALLOW_HTTP_AUTH") == "1" and args.provider == "datacenter")
    except ValueError as exc:
        parser.error(str(exc))
    inventory_function = cloud_inventory if args.provider == "cloud" else inventory
    return write_reports(args.output, {"source": "bitbucket", "provider": args.provider,
                                       "workspace": args.workspace if args.provider == "cloud" else None, "url": args.url,
                                       "projects": args.project, "additional_branches": args.branch,
                                       "request_delay_seconds": args.delay, "java_majors": args.java_majors},
                         *inventory_function(api, args))


if __name__ == "__main__":
    raise SystemExit(main())
