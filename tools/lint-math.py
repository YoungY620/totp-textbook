#!/usr/bin/env python3
"""Lint math spans for the one Markdown hazard the mathprotect preprocessor cannot fix.

pulldown-cmark decides emphasis before MathJax runs. Inside `$...$` a subscript whose
inner delimiter is a *punctuation* character — `}_{C}`, `)_{i}`, `'_{0}` — becomes a
left-flanking `_`, i.e. a legitimate emphasis *opener*. If any later `_` in the same
paragraph is a closer (preceded by an alphanumeric, e.g. the `_` in `H_{1}`), the pair
turns into `<em>…</em>` and rips the formula apart.

Rule of thumb: write `\mathsf{ID_C}` (subscript inside the macro) rather than
`\mathsf{ID}_{C}`, so every `_` sits immediately after a letter and can only close.

Usage: python3 tools/lint-math.py <dir-or-file> ...
Exit code 1 if any offender is found.
"""
import re
import sys
from pathlib import Path

PUNCT_BEFORE = set("})]'\"*")
# CommonMark treats all ASCII punctuation as punctuation for the flanking rules.
ASCII_PUNCT = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


def math_spans(text):
    """Yield (line_no, span) for math outside fenced/inline code."""
    i, n = 0, len(text)
    lineno = 1
    out = []
    while i < n:
        ch = text[i]
        if ch == "\n":
            lineno += 1
        if ch in "`~":
            fence = "```" if text.startswith("```", i) else ("~~~" if text.startswith("~~~", i) else None)
            if fence:
                nl = text.find("\n", i)
                if nl == -1:
                    break
                end = text.find("\n" + fence, nl)
                end = n if end == -1 else text.find("\n", end + 1)
                lineno += text.count("\n", i, end if end != -1 else n)
                i = end if end != -1 else n
                continue
        if ch == "`":
            k = i
            while k < n and text[k] == "`":
                k += 1
            end = text.find(text[i:k], k)
            end = n if end == -1 else end + len(text[i:k])
            lineno += text.count("\n", i, end)
            i = end
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if text.startswith("$$", i):
            end = text.find("$$", i + 2)
            if end == -1:
                break
            out.append((lineno, text[i + 2:end]))
            lineno += text.count("\n", i, end + 2)
            i = end + 2
            continue
        if ch == "$":
            j = i + 1
            if j < n and not text[j].isspace():
                k = j
                found = -1
                while k < n:
                    if text[k] == "\\":
                        k += 2
                        continue
                    if text[k] == "$":
                        found = k
                        break
                    if text[k] == "\n":
                        break
                    k += 1
                if found != -1 and not text[found - 1].isspace():
                    out.append((lineno, text[i + 1:found]))
                    i = found + 1
                    continue
        i += 1
    return out


def analyze(span):
    """Return indices of `_` that can open and that can close, using CommonMark's rules."""
    openers, closers = [], []
    for idx, c in enumerate(span):
        if c != "_":
            continue
        prev_c = span[idx - 1] if idx > 0 else ""
        next_c = span[idx + 1] if idx + 1 < len(span) else ""
        prev_punct = prev_c in ASCII_PUNCT or prev_c == ""
        next_punct = next_c in ASCII_PUNCT or next_c == ""
        next_space = next_c == "" or next_c == " "
        prev_space = prev_c == "" or prev_c == " "
        left_flanking = (not next_space) and ((not next_punct) or prev_space or prev_punct)
        right_flanking = (not prev_space) and ((not prev_punct) or next_space or next_punct)
        can_open = left_flanking and ((not right_flanking) or prev_punct)
        can_close = right_flanking and ((not left_flanking) or next_punct)
        if can_open:
            openers.append(idx)
        if can_close:
            closers.append(idx)
    # risk exists iff some opener has a closer after it
    return [(o, c) for o in openers for c in closers if c > o]


def check_file(path: Path):
    text = path.read_text(encoding="utf-8")
    problems = []
    for lineno, span in math_spans(text):
        for o, c in analyze(span):
            problems.append((lineno, span[max(0, o - 12):o + 14]))
            break
    return problems


def main(argv):
    targets = []
    for a in argv:
        p = Path(a)
        targets += sorted(p.rglob("*.md")) if p.is_dir() else [p]
    total = 0
    for f in targets:
        for lineno, snippet in check_file(f):
            total += 1
            print(f"{f}:{lineno}: emphasis-risk subscript near `{snippet}`")
    if total:
        print("\n%d risky subscript(s). The mathprotect preprocessor fixes these at build "
              "time, but clean sources are easier to review." % total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
