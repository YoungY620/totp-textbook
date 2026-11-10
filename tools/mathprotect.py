#!/usr/bin/env python3
"""mdBook preprocessor: protect LaTeX math spans from Markdown mangling.

pulldown-cmark (mdBook's Markdown parser) runs before MathJax and mangles math two ways:

1. Backslash escapes are consumed, so `\\\\` becomes `\\`, `\\{` becomes `{`,
   `\\,` becomes `,`. Fix: double every backslash, so the parser emits exactly the
   single backslashes MathJax needs.

2. Emphasis is decided before MathJax sees anything. A subscript whose base ends in
   punctuation — `\\mathsf{ID}_{C}`, `e^{\\prime}_{pw}` — becomes a left-flanking `_`,
   i.e. a valid emphasis *opener*; if any later `_` in the paragraph is a closer
   (the `_` in a normal `H_{1}`), the pair turns into `<em>…</em>` and rips the
   formula apart. Fix: escape `_` and `*` as `\\_`/`\\*`, so the parser emits a bare
   `_` (a subscript for MathJax) and never treats it as a delimiter.

**Raw HTML blocks** (our `.source-card` / `.aside` / `.hook` divs) are a third case:
CommonMark passes them through verbatim, so no escaping happens there. Applying the
transform inside them would hand MathJax `\\\\text` (a line break plus the word
"text") and `\\_` (a literal underscore). So math inside a raw HTML block is left
completely untouched.

Everything outside math — and all raw HTML blocks — is byte-for-byte preserved.
"""
import json
import re
import sys

# CommonMark HTML-block type 6: a line starting with one of these block tags.
BLOCK_TAG = re.compile(
    r"^ {0,3}</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|"
    r"col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|"
    r"form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|"
    r"menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|"
    r"tbody|td|tfoot|th|thead|title|tr|track|ul)\b",
    re.IGNORECASE,
)


def escape_math(body: str) -> str:
    """Make a math body survive the Markdown round trip unchanged for MathJax."""
    out = []
    for ch in body:
        if ch == "\\":
            out.append("\\\\")      # parser: \\ -> \
        elif ch in "_*":
            out.append("\\" + ch)   # parser: \_ -> _   (blocks emphasis)
        else:
            out.append(ch)
    return "".join(out)


def protect_math(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        # --- fenced code block: copy verbatim ---
        if ch in "`~":
            fence = None
            if text.startswith("```", i):
                fence = "```"
            elif text.startswith("~~~", i):
                fence = "~~~"
            if fence:
                nl = text.find("\n", i)
                if nl == -1:
                    out.append(text[i:])
                    break
                end = text.find("\n" + fence, nl)
                if end == -1:
                    out.append(text[i:])
                    break
                end = text.find("\n", end + 1)
                if end == -1:
                    end = n
                out.append(text[i:end])
                i = end
                continue

        # --- inline code: copy verbatim ---
        if ch == "`":
            k = i
            while k < n and text[k] == "`":
                k += 1
            end = text.find(text[i:k], k)
            if end == -1:
                out.append(text[i:])
                break
            end += len(text[i:k])
            out.append(text[i:end])
            i = end
            continue

        # --- backslash escape outside math: keep as is ---
        if ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue

        # --- display math $$...$$ (may span lines) ---
        if text.startswith("$$", i):
            end = text.find("$$", i + 2)
            if end == -1:
                out.append(text[i:])
                break
            out.append("$$" + escape_math(text[i + 2:end]) + "$$")
            i = end + 2
            continue

        # --- inline math $...$ (single line, no surrounding spaces) ---
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
                    out.append("$" + escape_math(text[i + 1:found]) + "$")
                    i = found + 1
                    continue
            out.append(text[i])
            i += 1
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def protect_document(text: str) -> str:
    """Apply math protection outside raw HTML blocks; leave those blocks verbatim."""
    lines = text.split("\n")
    out = []
    i = 0
    n = len(lines)
    while i < n:
        if BLOCK_TAG.match(lines[i]):
            # HTML block: runs to the first blank line (CommonMark type 6).
            j = i
            while j < n and lines[j].strip() != "":
                j += 1
            out.append("\n".join(lines[i:j]))
            i = j
        else:
            j = i
            while j < n and not BLOCK_TAG.match(lines[j]):
                j += 1
            out.append(protect_math("\n".join(lines[i:j])))
            i = j
    return "\n".join(out)


def walk(items):
    for item in items:
        if "Chapter" in item:
            chapter = item["Chapter"]
            if isinstance(chapter.get("content"), str):
                chapter["content"] = protect_document(chapter["content"])
            walk(chapter.get("sub_items", []))


def main():
    args = sys.argv[1:]
    if args and args[0] == "supports":
        return 0
    payload = json.load(sys.stdin)
    if len(payload) < 2:
        json.dump(payload, sys.stdout)
        return 0
    book = payload[1]
    walk(book.get("items", []))
    # mdBook 0.5 expects the (modified) book object on stdout.
    json.dump(book, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
