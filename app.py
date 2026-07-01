import os
import re
import requests

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]"),
    ("GitHub PAT", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth", r"gho_[0-9a-zA-Z]{36}"),
    ("GitHub App Token", r"ghs_[0-9a-zA-Z]{36}"),
    ("GitHub Refresh", r"ghr_[0-9a-zA-Z]{36}"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    ("Private Key", r"-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY-----"),
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    ("Twitter API Secret", r"(?i)twitter(.{0,20})?['\"][0-9a-zA-Z]{35,44}['\"]"),
    ("Facebook Secret", r"(?i)facebook(.{0,20})?['\"][0-9a-zA-Z]{32,40}['\"]"),
    ("Discord Bot Token", r"[Mm][Nn][Ss][Tt][Tt][Yy].[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
    ("npm token", r"npm_[a-zA-Z0-9]{36}"),
    ("PyPI token", r"pypi-[A-Za-z0-9]{32,}"),
    ("Docker Hub Password", r"(?i)docker(.{0,20})?['\"][a-zA-Z0-9_\-]{20,}['\"]"),
    ("Generic Password", r"(?i)(password|passwd|pwd|secret)(.{0,20})?['\"][^'\"]{8,}['\"]"),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey|api_secret)(.{0,20})?['\"][a-zA-Z0-9_\-]{16,64}['\"]"),
    ("Connection String", r"(?i)(connection\s*string|conn_string|connstr)(.{0,20})?['\"][^'\"]+['\"]"),
    ("MongoDB URI", r"mongodb(?:\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("MySQL URI", r"mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("PostgreSQL URI", r"postgres(ql)?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
    ("Redis URI", r"redis://[a-zA-Z0-9]+:[a-zA-Z0-9]+@"),
]

EXCLUDE_PATTERNS = [
    r"\.git/",
    r"node_modules/",
    r"vendor/",
    r"\.venv/",
    r"__pycache__/",
    r"\.next/",
    r"dist/",
    r"build/",
    r"\.png$",
    r"\.jpg$",
    r"\.jpeg$",
    r"\.gif$",
    r"\.svg$",
    r"\.ico$",
    r"\.woff2?$",
    r"\.eot$",
    r"\.ttf$",
    r"\.pdf$",
    r"\.zip$",
    r"\.gz$",
    r"\.lock$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"\.min\.(js|css)$",
    r"app\.py$",
    r"templates/",
    r"__tests__/",
    r"test_",
    r"_test\.",
]

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".c", ".h", ".hpp",
    ".rb", ".go", ".rs", ".swift", ".kt", ".scala", ".php", ".cs", ".fs",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".env.example", ".txt", ".md", ".rst", ".html", ".css", ".scss",
    ".sql", ".r", ".m", ".mm", ".pl", ".pm", ".lua", ".vue", ".svelte",
    ".tf", ".tfvars", ".dockerfile", ".makefile", ".gradle", ".sbt",
    ".ex", ".exs", ".erl", ".hrl", ".clj", ".cljs", ".edn",
    "Dockerfile", "Makefile", "Gemfile", "Rakefile",
}

MAX_FILE_SIZE = 1024 * 100
MAX_FILES = 100


def should_scan(path):
    path_lower = path.lower()
    for pat in EXCLUDE_PATTERNS:
        if re.search(pat, path_lower):
            return False
    ext = os.path.splitext(path)[1].lower()
    basename = os.path.basename(path)
    if ext in TEXT_EXTENSIONS or basename in TEXT_EXTENSIONS:
        return True
    for t in TEXT_EXTENSIONS:
        if basename.lower() == t.lower():
            return True
    return False


def mask_secret(text, pattern):
    match = re.search(pattern, text)
    if match:
        val = match.group()
        if len(val) > 8:
            return val[:4] + "*" * (len(val) - 8) + val[-4:]
        return "*" * len(val)
    return "***"


def scan_content(content, filepath):
    findings = []
    for name, pattern in SECRET_PATTERNS:
        for i, line in enumerate(content.split("\n"), 1):
            if re.search(pattern, line):
                masked = mask_secret(line, pattern)
                findings.append({
                    "type": name,
                    "file": filepath,
                    "line": i,
                    "snippet": masked.strip()[:200],
                })
    return findings


def get_repo_default_branch(owner, repo):
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", timeout=10)
    if r.status_code == 200:
        return r.json().get("default_branch", "main")
    return "main"


def fetch_file_content(owner, repo, path, branch):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    r = requests.get(url, timeout=15)
    if r.status_code == 200:
        return r.text
    return None


def list_repo_files(owner, repo, branch):
    files = []
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        return files
    tree = r.json().get("tree", [])
    for item in tree:
        if item["type"] == "blob":
            files.append(item["path"])
    return files


def parse_github_url(url):
    url = url.rstrip("/")
    if "github.com/" not in url:
        return None, None, None
    parts = url.split("github.com/")[1].split("/")
    if len(parts) < 2:
        return None, None, None
    owner = parts[0]
    repo = parts[1].replace(".git", "")
    branch = None
    if len(parts) > 3 and parts[2] == "tree":
        branch = parts[3]
    return owner, repo, branch


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    repo_url = data.get("url", "").strip()

    if not repo_url:
        return jsonify({"error": "No URL provided. Paste a GitHub repo URL like: https://github.com/owner/repo"}), 400

    if "github.com" not in repo_url:
        return jsonify({"error": "This doesn't look like a GitHub URL. Make sure it starts with: https://github.com/owner/repo"}), 400

    owner, repo, branch = parse_github_url(repo_url)
    if not owner or not repo:
        return jsonify({"error": "Could not find the repo in that URL. Use format: https://github.com/owner/repo (e.g. https://github.com/gnaixnaij/cyber-cheatsheet)"}), 400

    try:
        if not branch:
            branch = get_repo_default_branch(owner, repo)
        files = list_repo_files(owner, repo, branch)
        if not files:
            return jsonify({"error": "Could not fetch repo. Is it public?"}), 400

        scan_files = [f for f in files if should_scan(f)][:MAX_FILES]
        total_scanned = len(scan_files)
        total_skipped = len(files) - total_scanned

        all_findings = []
        for i, filepath in enumerate(scan_files):
            content = fetch_file_content(owner, repo, filepath, branch)
            if content and len(content) <= MAX_FILE_SIZE:
                findings = scan_content(content, filepath)
                all_findings.extend(findings)

        severity_count = {"high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            if "Private Key" in f["type"] or "AWS" in f["type"]:
                severity_count["high"] += 1
            elif "Token" in f["type"] or "Secret" in f["type"]:
                severity_count["medium"] += 1
            else:
                severity_count["low"] += 1

        return jsonify({
            "repo": f"{owner}/{repo}",
            "branch": branch,
            "total_files": len(files),
            "scanned_files": total_scanned,
            "skipped_files": total_skipped,
            "findings": all_findings,
            "total_findings": len(all_findings),
            "severity": severity_count,
        })

    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Large repos may not work. Try a smaller repo."}), 504
    except re.error:
        return jsonify({"error": "Internal scanning error. Please report this on GitHub."}), 500
    except Exception as e:
        return jsonify({"error": str(e)[:200]}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
