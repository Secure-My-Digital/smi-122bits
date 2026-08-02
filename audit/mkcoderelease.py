#!/usr/bin/env python3
"""
N1 fix — robust code-release.json generator.

Run from the REPOSITORY ROOT with git-crypt UNLOCKED:

    git-crypt unlock         # so protected sources are readable as plaintext
    python3 audit/mkcode-release.py

Improvements over the old audit/mkcode-release.sh:
  * clean repo-root-relative paths (no more `../` prefix);
  * fails LOUD if any listed file is missing or still git-crypt encrypted
    (the old pipeline silently emitted stale/encrypted content);
  * reads the file list from deploy.yml (publish.files) with a tiny parser
    (no json_xs / mkjson.pl dependency).
"""
import json
import os
import subprocess
import sys
import time

GITCRYPT_MAGIC = b"\x00GITCRYPT\x00"


def read_publish_files(deploy_yml="deploy.yml"):
    files, in_files = [], False
    for line in open(deploy_yml, encoding="utf-8"):
        s = line.strip()
        if s.startswith("files:"):
            in_files = True
            continue
        if in_files:
            if s.startswith("- "):
                files.append(s[2:].strip())
            elif s and not s.startswith("#") and not s.startswith("-"):
                break  # left the files: block
    return files


def git_short(path):
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", f"HEAD:{path}"],
            stderr=subprocess.DEVNULL).decode().strip()
    except subprocess.CalledProcessError:
        return ""


def main():
    if not os.path.exists("deploy.yml"):
        sys.exit("[FATAL] run from the repository root (deploy.yml not found).")
    files = read_publish_files()
    out, problems = [], []
    for path in files:
        if not os.path.exists(path):
            problems.append(f"missing: {path}")
            continue
        raw = open(path, "rb").read()
        if raw.startswith(GITCRYPT_MAGIC):
            problems.append(f"still encrypted (run `git-crypt unlock`): {path}")
            continue
        st = os.stat(path)
        out.append({
            "content": raw.decode("utf-8", errors="replace"),
            "date": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            "filePath": path,                       # clean, repo-root-relative
            "gitid": git_short(path),
            "size": str(len(raw)),
        })
    if problems:
        sys.exit("[FATAL] refusing to write a stale/incomplete release:\n  "
                 + "\n  ".join(problems))
    with open("audit/code-release.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=3)
    print(f"[OK] audit/code-release.json — {len(out)} files, no encrypted/missing entries.")


if __name__ == "__main__":
    main()
