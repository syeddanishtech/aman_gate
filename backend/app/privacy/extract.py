"""Local text extraction for .txt, born-digital .pdf (pypdf) and .docx (stdlib zipfile + xml only).

Everything runs in-process on bytes: no network, no external converter, no OCR. The result is an
ExtractedDocument whose segments are located runs of text:

  body segments          the visible document text (the only thing a safe artifact can be built from)
  everything else        metadata (PDF info + XMP, OOXML core/app/custom props), comments, tracked
                         deletions, hidden (vanish) text, field codes, annotations, link targets,
                         form fields. These are extracted so they can be SCANNED, then omitted.

Fail closed: anything unsupported or uncertain makes the document REVIEW_REQUIRED with machine-readable
reason codes (never raw content), and the sanitizer then refuses to export it. That includes a scanned /
image-only PDF, any embedded image or drawing (image / OCR / logo handling is Phase 2 and is detected and
blocked here, not guessed at), encrypted or malformed files, macros, active content, XML DTDs/entities,
oversized or unexpected package parts, and a file whose bytes disagree with its extension.
"""
from __future__ import annotations

import hashlib
import io
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping

from .graph import BODY_KIND, TextSegment

STATUS_OK = "OK"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"

MEDIA_TEXT = "text/plain"
MEDIA_PDF = "application/pdf"
MEDIA_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
MEDIA_UNKNOWN = "application/octet-stream"

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_PART_BYTES = 16 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_PDF_PAGES = 300
MAX_EXTRACTED_CHARS = 2_000_000

_DOCX_MAIN_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"


@dataclass(frozen=True)
class ExtractedDocument:
    media_type: str
    source_sha256: str
    status: str
    review_reasons: tuple[str, ...] = ()
    segments: tuple[TextSegment, ...] = ()
    features: Mapping[str, Any] = field(default_factory=dict)  # counts / booleans only, never content

    @property
    def review_required(self) -> bool:
        return self.status != STATUS_OK

    @property
    def body_text(self) -> str:
        return "\n\n".join(s.text for s in self.segments if s.kind == BODY_KIND)

    def to_record(self) -> dict[str, Any]:
        """JSON-safe view for decision records: status, reason codes and feature flags. No text."""
        return {"media_type": self.media_type, "status": self.status,
                "review_reasons": list(self.review_reasons), "features": dict(sorted(self.features.items()))}


class _Uncertain(Exception):
    """Internal: extraction cannot be trusted. `code` becomes a review reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _review(media: str, sha: str, reasons: list[str], features: Mapping[str, Any] | None = None) -> ExtractedDocument:
    """REVIEW_REQUIRED result. Segments are deliberately dropped: nothing partial is ever handed on."""
    return ExtractedDocument(media, sha, STATUS_REVIEW_REQUIRED, tuple(dict.fromkeys(reasons)), (), features or {})


# ---------------------------------------------------------------------------- plain text
def extract_text_bytes(data: bytes, *, media_type: str = MEDIA_TEXT) -> ExtractedDocument:
    sha = _sha(data)
    if len(data) > MAX_INPUT_BYTES:
        return _review(media_type, sha, ["INPUT_TOO_LARGE"])
    if b"\x00" in data:
        return _review(media_type, sha, ["BINARY_CONTENT"])
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _review(media_type, sha, ["TEXT_DECODE_ERROR"])  # no encoding guessing
    if any(ord(c) < 32 and c not in "\t\n\r\f" for c in text):
        return _review(media_type, sha, ["CONTROL_CHARACTERS"])
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return ExtractedDocument(media_type, sha, STATUS_OK, (), (TextSegment(BODY_KIND, BODY_KIND, text),),
                             {"chars": len(text)})


# ---------------------------------------------------------------------------- XML helpers
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


_DTD_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _safe_xml(data: bytes) -> ET.Element:
    """Parse untrusted XML. DTDs and entity declarations are rejected outright (no expansion attacks)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data:
        raise _Uncertain("XML_UNSUPPORTED_ENCODING")
    if _DTD_RE.search(data):
        raise _Uncertain("XML_DTD_REJECTED")
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        raise _Uncertain("XML_PARSE_ERROR") from None


def _flatten_xml(root: ET.Element) -> list[str]:
    """Every non-empty text node and attribute value, as 'name: value' lines."""
    lines: list[str] = []
    for el in root.iter():
        name = _local(el.tag)
        t = (el.text or "").strip()
        if t:
            lines.append(f"{name}: {t}")
        for k, v in el.attrib.items():
            v = v.strip()
            if v:
                lines.append(f"{name}@{_local(k)}: {v}")
    return lines


# ---------------------------------------------------------------------------- DOCX
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_MC = "{http://schemas.openxmlformats.org/markup-compatibility/2006}"
_GRAPHIC_TAGS = frozenset({_W + "drawing", _W + "pict", _W + "object"})

_BODY_PART = re.compile(r"^word/(document|footnotes|endnotes|header\d{0,3}|footer\d{0,3})\.xml$")
_IGNORABLE_PART = re.compile(
    r"^(\[Content_Types\]\.xml|_rels/\.rels|word/_rels/[^/]+\.rels"
    r"|word/(styles|stylesWithEffects|settings|webSettings|fontTable|numbering|commentsExtended|commentsIds"
    r"|commentsExtensible|people)\.xml|word/theme/theme\d{0,3}\.xml"
    r"|customXml/itemProps\d+\.xml|customXml/_rels/[^/]+\.rels)$")
_GRAPHIC_PART = re.compile(r"^(word/(media|embeddings|charts|diagrams|drawings|ink)/|docProps/thumbnail)")
_ACTIVE_PART = re.compile(r"^word/(vbaProject\.bin|vbaData\.xml|activeX/)")


class _Walker:
    """Walks WordprocessingML in document order, routing text by what it is (visible / deleted / hidden)."""

    def __init__(self) -> None:
        self.deleted: list[str] = []
        self.hidden: list[str] = []
        self.fields: list[str] = []
        self.flags: set[str] = set()

    @staticmethod
    def _first_choice(alt: ET.Element) -> ET.Element | None:
        return next((c for c in alt if c.tag == _MC + "Choice"), None)

    def lines(self, root: ET.Element) -> list[str]:
        out: list[str] = []
        self._blocks(root, out)
        return out

    def _blocks(self, el: ET.Element, out: list[str]) -> None:
        for child in el:
            tag = child.tag
            if tag == _W + "p":
                self._paragraph(child, out)
            elif tag == _MC + "AlternateContent":
                choice = self._first_choice(child)  # the Fallback is a duplicate rendering: skip it
                if choice is not None:
                    self._blocks(choice, out)
            elif tag in _GRAPHIC_TAGS:
                self.flags.add("GRAPHIC")
            elif tag == _W + "altChunk":
                self.flags.add("ALT_CHUNK")
            elif tag in (_W + "ins", _W + "moveTo"):
                self.flags.add("TRACKED_CHANGES")
                self._blocks(child, out)
            elif tag in (_W + "del", _W + "moveFrom"):
                self.flags.add("TRACKED_CHANGES")
                scratch: list[str] = []
                self._blocks(child, scratch)
                self.deleted.extend(s for s in scratch if s.strip())
            else:
                self._blocks(child, out)

    def _paragraph(self, p: ET.Element, out: list[str]) -> None:
        buf: dict[str, list[str]] = {"body": [], "deleted": [], "hidden": [], "fields": []}
        self._inline(p, buf, deleted=False)
        out.append("".join(buf["body"]))
        for key, sink in (("deleted", self.deleted), ("hidden", self.hidden), ("fields", self.fields)):
            s = "".join(buf[key]).strip()
            if s:
                sink.append(s)

    def _inline(self, el: ET.Element, buf: dict[str, list[str]], deleted: bool) -> None:
        for child in el:
            tag = child.tag
            if tag == _W + "pPr":
                if child.find(f"{_W}rPr/{_W}del") is not None or child.find(f"{_W}rPr/{_W}ins") is not None:
                    self.flags.add("TRACKED_CHANGES")
            elif tag == _W + "r":
                self._run(child, buf, deleted)
            elif tag in (_W + "ins", _W + "moveTo"):
                self.flags.add("TRACKED_CHANGES")
                self._inline(child, buf, deleted)
            elif tag in (_W + "del", _W + "moveFrom"):
                self.flags.add("TRACKED_CHANGES")
                self._inline(child, buf, True)
            elif tag == _W + "fldSimple":
                instr = child.get(_W + "instr")
                if instr:
                    buf["fields"].append(instr + " ")
                self._inline(child, buf, deleted)
            elif tag == _MC + "AlternateContent":
                choice = self._first_choice(child)
                if choice is not None:
                    self._inline(choice, buf, deleted)
            elif tag in _GRAPHIC_TAGS:
                self.flags.add("GRAPHIC")
            elif tag == _W + "p":
                self.flags.add("UNEXPECTED_STRUCTURE")
            else:  # hyperlink, sdt, sdtContent, smartTag, customXml, bookmarks, ...
                self._inline(child, buf, deleted)

    def _run(self, r: ET.Element, buf: dict[str, list[str]], deleted: bool) -> None:
        hidden = False
        rpr = r.find(_W + "rPr")
        if rpr is not None:
            for name in ("vanish", "specVanish"):
                v = rpr.find(_W + name)
                if v is not None and v.get(_W + "val", "true").lower() not in ("0", "false", "off"):
                    hidden = True
        for child in r:
            tag = child.tag
            text = ""
            kind = "body"
            if tag == _W + "t":
                text = child.text or ""
            elif tag == _W + "delText":
                text, kind = child.text or "", "deleted"
            elif tag == _W + "instrText":
                buf["fields"].append(child.text or "")
                continue
            elif tag == _W + "tab":
                text = "\t"
            elif tag in (_W + "br", _W + "cr"):
                text = "\n"
            elif tag == _W + "noBreakHyphen":
                text = "-"
            elif tag in _GRAPHIC_TAGS:
                self.flags.add("GRAPHIC")
                continue
            elif tag == _MC + "AlternateContent":
                if any(d.tag in _GRAPHIC_TAGS for d in child.iter()):
                    self.flags.add("GRAPHIC")
                continue
            else:
                continue
            if deleted:
                kind = "deleted"
            elif hidden and kind == "body":
                kind = "hidden"
            buf[kind].append(text)


def _joined(lines: list[str]) -> str:
    return "\n".join(lines)


def extract_docx(data: bytes) -> ExtractedDocument:
    sha = _sha(data)
    if len(data) > MAX_INPUT_BYTES:
        return _review(MEDIA_DOCX, sha, ["INPUT_TOO_LARGE"])
    try:
        return _extract_docx(data, sha)
    except _Uncertain as u:
        return _review(MEDIA_DOCX, sha, [u.code])
    except Exception:  # fail closed on any parser surprise
        return _review(MEDIA_DOCX, sha, ["DOCX_PARSE_ERROR"])


def _extract_docx(data: bytes, sha: str) -> ExtractedDocument:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise _Uncertain("NOT_A_VALID_ZIP") from None
    with zf:
        infos = [i for i in zf.infolist() if not i.filename.endswith("/")]
        if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED:
            raise _Uncertain("ZIP_LIMITS_EXCEEDED")
        names = [i.filename for i in infos]
        if len(set(names)) != len(names):
            raise _Uncertain("DUPLICATE_PART_NAME")
        if any(i.flag_bits & 0x1 for i in infos):
            raise _Uncertain("ENCRYPTED_PACKAGE")
        for n in names:
            p = PurePosixPath(n)
            if "\\" in n or n.startswith("/") or ".." in p.parts:
                raise _Uncertain("UNSAFE_PART_NAME")
        by_name = {i.filename: i for i in infos}

        def read(name: str) -> bytes:
            info = by_name[name]
            if info.file_size > MAX_PART_BYTES:
                raise _Uncertain("ZIP_LIMITS_EXCEEDED")
            with zf.open(info) as fh:
                buf = fh.read(MAX_PART_BYTES + 1)
            if len(buf) > MAX_PART_BYTES:
                raise _Uncertain("ZIP_LIMITS_EXCEEDED")
            return buf

        if "[Content_Types].xml" not in by_name or "word/document.xml" not in by_name:
            raise _Uncertain("NOT_A_DOCX")
        ct_root = _safe_xml(read("[Content_Types].xml"))
        main_types = [o.get("ContentType") for o in ct_root.iter()
                      if _local(o.tag) == "Override" and o.get("PartName") == "/word/document.xml"]
        if main_types != [_DOCX_MAIN_CT]:
            raise _Uncertain("NOT_A_DOCX")  # includes macro-enabled (.docm) and template main parts

        reasons: list[str] = []
        walker = _Walker()
        body_segments: list[TextSegment] = []
        extra: list[TextSegment] = []
        metadata_fields = 0
        comment_count = 0
        link_lines: list[str] = []

        for name in sorted(by_name):
            if _BODY_PART.match(name):
                lines = walker.lines(_safe_xml(read(name)))
                body_segments.append(TextSegment(f"docx:{name}", BODY_KIND, _joined(lines)))
            elif name == "word/comments.xml":
                root = _safe_xml(read(name))
                clines = []
                for c in root.iter(_W + "comment"):
                    w = _Walker()
                    w_lines = w.lines(c)
                    flat = " ".join(x for x in w_lines + w.deleted + w.hidden if x.strip())
                    clines.append(f"{c.get(_W + 'author', '')}: {flat}")
                    walker.flags |= w.flags
                comment_count = len(clines)
                if clines:
                    extra.append(TextSegment("docx:comments", "comments", _joined(clines)))
            elif name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
                mlines = _flatten_xml(_safe_xml(read(name)))
                metadata_fields += len(mlines)
                if mlines:
                    extra.append(TextSegment(f"docx:{name}", "metadata", _joined(mlines)))
            elif re.match(r"^customXml/item\d+\.xml$", name):
                clines2 = _flatten_xml(_safe_xml(read(name)))
                if clines2:
                    extra.append(TextSegment(f"docx:{name}", "custom_xml", _joined(clines2)))
            elif name.startswith("word/_rels/") and name.endswith(".rels"):
                for rel in _safe_xml(read(name)):
                    if rel.get("TargetMode") == "External":
                        link_lines.append(f"{rel.get('Type', '').rsplit('/', 1)[-1]}: {rel.get('Target', '')}")
            elif _ACTIVE_PART.match(name):
                reasons.append("MACROS_PRESENT")
            elif _GRAPHIC_PART.match(name):
                reasons.append("GRAPHIC_CONTENT_UNREVIEWED")
            elif not _IGNORABLE_PART.match(name):
                reasons.append("UNPARSED_PARTS")

        if link_lines:
            extra.append(TextSegment("docx:links", "links", _joined(sorted(set(link_lines)))))
        for seg_name, kind, lines in (("docx:tracked_deletions", "tracked_deletions", walker.deleted),
                                      ("docx:hidden_text", "hidden_text", walker.hidden),
                                      ("docx:field_codes", "field_codes", walker.fields)):
            if lines:
                extra.append(TextSegment(seg_name, kind, _joined(lines)))

        if "GRAPHIC" in walker.flags:
            reasons.append("GRAPHIC_CONTENT_UNREVIEWED")
        if "ALT_CHUNK" in walker.flags:
            reasons.append("UNPARSED_PARTS")
        if "UNEXPECTED_STRUCTURE" in walker.flags:
            reasons.append("DOCX_PARSE_ERROR")

        segments = tuple(body_segments + extra)
        if sum(len(s.text) for s in segments) > MAX_EXTRACTED_CHARS:
            reasons.append("TEXT_LIMIT_EXCEEDED")

        features = {
            "parts": len(names),
            "body_parts": len(body_segments),
            "tracked_changes": "TRACKED_CHANGES" in walker.flags,
            "comments": comment_count,
            "hidden_text": bool(walker.hidden),
            "field_codes": bool(walker.fields),
            "external_links": len(set(link_lines)),
            "metadata_fields": metadata_fields,
        }
        if reasons:
            return _review(MEDIA_DOCX, sha, reasons, features)
        return ExtractedDocument(MEDIA_DOCX, sha, STATUS_OK, (), segments, features)


# ---------------------------------------------------------------------------- PDF
def _obj(x: Any) -> Any:
    """Resolve a pypdf indirect reference (direct objects resolve to themselves)."""
    return x.get_object() if hasattr(x, "get_object") else x


def _resources_have_images(res: Any, depth: int = 0) -> bool:
    if res is None:
        return False
    if depth > 6:
        raise _Uncertain("PDF_PARSE_ERROR")
    xobjs = _obj(res).get("/XObject")
    if xobjs is None:
        return False
    for ref in _obj(xobjs).values():
        xo = _obj(ref)
        subtype = _obj(xo.get("/Subtype"))
        if subtype == "/Image":
            return True
        if subtype == "/Form" and _resources_have_images(xo.get("/Resources"), depth + 1):
            return True
    return False


def _page_has_images(page: Any) -> bool:
    if _resources_have_images(page.get("/Resources")):
        return True
    contents = page.get_contents()
    if contents is not None:
        return any(op == b"INLINE IMAGE" for _operands, op in contents.operations)
    return False


def extract_pdf(data: bytes) -> ExtractedDocument:
    sha = _sha(data)
    if len(data) > MAX_INPUT_BYTES:
        return _review(MEDIA_PDF, sha, ["INPUT_TOO_LARGE"])
    try:
        return _extract_pdf(data, sha)
    except _Uncertain as u:
        return _review(MEDIA_PDF, sha, [u.code])
    except Exception:  # malformed / hostile PDFs: fail closed
        return _review(MEDIA_PDF, sha, ["PDF_PARSE_ERROR"])


def _extract_pdf(data: bytes, sha: str) -> ExtractedDocument:
    from pypdf import PdfReader  # local import keeps module import cheap for text-only callers

    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted:
        raise _Uncertain("PDF_ENCRYPTED")
    n_pages = len(reader.pages)
    if n_pages == 0:
        raise _Uncertain("PDF_NO_PAGES")
    if n_pages > MAX_PDF_PAGES:
        raise _Uncertain("PDF_LIMITS_EXCEEDED")

    reasons: list[str] = []
    root = reader.trailer["/Root"]
    if any(k in root for k in ("/OpenAction", "/AA", "/Collection")):
        reasons.append("PDF_ACTIVE_CONTENT")
    names = root.get("/Names")
    if names is not None and any(k in _obj(names) for k in ("/JavaScript", "/EmbeddedFiles")):
        reasons.append("PDF_ACTIVE_CONTENT")
    acro = root.get("/AcroForm")
    if acro is not None and "/XFA" in _obj(acro):
        reasons.append("PDF_ACTIVE_CONTENT")

    body: list[TextSegment] = []
    annot_lines: list[str] = []
    link_lines: list[str] = []
    pages_without_text = 0
    images = False
    for i, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if text:
            body.append(TextSegment(f"pdf:page:{i}", BODY_KIND, text))
        else:
            pages_without_text += 1
        if _page_has_images(page):
            images = True
        if "/AA" in page:
            reasons.append("PDF_ACTIVE_CONTENT")
        annots = page.get("/Annots")
        if annots is not None:
            for ref in _obj(annots):
                a = _obj(ref)
                if _obj(a.get("/Subtype")) == "/FileAttachment":
                    reasons.append("PDF_ACTIVE_CONTENT")
                for key in ("/Contents", "/T", "/Subj", "/V", "/RC"):
                    val = _obj(a.get(key))
                    if val is not None and str(val).strip():
                        annot_lines.append(f"{key[1:]}: {val}")
                action = a.get("/A")
                if action is not None:
                    action = _obj(action)
                    if _obj(action.get("/S")) in ("/JavaScript", "/Launch", "/ImportData", "/SubmitForm"):
                        reasons.append("PDF_ACTIVE_CONTENT")
                    uri = _obj(action.get("/URI"))
                    if uri is not None:
                        link_lines.append(f"URI: {uri}")

    if pages_without_text == n_pages:
        reasons.append("PDF_NO_EXTRACTABLE_TEXT")  # scanned / image-only: nothing safe to read
    elif pages_without_text:
        reasons.append("PDF_PAGE_WITHOUT_TEXT")
    if images:
        reasons.append("PDF_IMAGES_UNREVIEWED")  # Phase 2 (image / OCR / logo review): detect and block

    extra: list[TextSegment] = []
    info_lines: list[str] = []
    meta = reader.metadata
    if meta is not None:
        info_lines = [f"{k}: {_obj(meta[k])}" for k in meta if str(_obj(meta[k])).strip()]
    if info_lines:
        extra.append(TextSegment("pdf:metadata:info", "metadata", _joined(info_lines)))
    xmp_lines: list[str] = []
    md = root.get("/Metadata")
    if md is not None:
        xmp_lines = _flatten_xml(_safe_xml(_obj(md).get_data()))
    if xmp_lines:
        extra.append(TextSegment("pdf:metadata:xmp", "metadata", _joined(xmp_lines)))
    if annot_lines:
        extra.append(TextSegment("pdf:annotations", "annotations", _joined(annot_lines)))
    if link_lines:
        extra.append(TextSegment("pdf:links", "links", _joined(sorted(set(link_lines)))))
    fields = reader.get_fields() or {}
    form_lines = [f"{name}: {_obj(f.get('/V'))}" for name, f in fields.items() if f.get("/V") is not None]
    if form_lines:
        extra.append(TextSegment("pdf:form_fields", "form_fields", _joined(form_lines)))

    segments = tuple(body + extra)
    if sum(len(s.text) for s in segments) > MAX_EXTRACTED_CHARS:
        reasons.append("TEXT_LIMIT_EXCEEDED")
    features = {
        "pages": n_pages, "pages_without_text": pages_without_text, "images_present": images,
        "metadata_fields": len(info_lines) + len(xmp_lines), "xmp_present": bool(xmp_lines),
        "annotations": len(annot_lines), "form_fields": len(form_lines),
    }
    if reasons:
        return _review(MEDIA_PDF, sha, reasons, features)
    return ExtractedDocument(MEDIA_PDF, sha, STATUS_OK, (), segments, features)


# ---------------------------------------------------------------------------- dispatcher
_EXT_KIND = {".txt": "text", ".pdf": "pdf", ".docx": "docx"}


def _sniff(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "docx"  # a zip: extract_docx confirms it really is a Word package
    return "text"


def extract_document(data: bytes, filename: str | None = None) -> ExtractedDocument:
    """Extract by content, cross-checked against the file extension. Never raises."""
    if not isinstance(data, (bytes, bytearray)):
        return _review(MEDIA_UNKNOWN, "", ["NOT_BYTES"])
    data = bytes(data)
    sha = _sha(data)
    sniffed = _sniff(data)
    if filename is not None:
        ext = PurePosixPath(filename.replace("\\", "/")).suffix.lower()
        declared = _EXT_KIND.get(ext)
        if declared is None:
            return _review(MEDIA_UNKNOWN, sha, ["UNSUPPORTED_TYPE"])
        if declared != sniffed:
            return _review(MEDIA_UNKNOWN, sha, ["TYPE_MISMATCH"])
    if sniffed == "pdf":
        return extract_pdf(data)
    if sniffed == "docx":
        return extract_docx(data)
    return extract_text_bytes(data)
