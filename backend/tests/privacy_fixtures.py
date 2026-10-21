"""Tiny synthetic DOCX / PDF builders for the privacy tests. Everything is generated in memory:
no committed binaries, no network, synthetic content only."""
from __future__ import annotations

import io
import zipfile
from xml.sax.saxutils import escape

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"
DOCX_MAIN_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
DOCM_MAIN_CT = "application/vnd.ms-word.document.macroEnabled.main+xml"
XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'


# ------------------------------------------------------------------ DOCX
def run(text: str, *, vanish: bool = False) -> str:
    rpr = "<w:rPr><w:vanish/></w:rPr>" if vanish else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def ins(text: str) -> str:
    return f'<w:ins w:id="1" w:author="Omar Siddiqui" w:date="2026-01-01T00:00:00Z">{run(text)}</w:ins>'


def dele(text: str) -> str:
    return (f'<w:del w:id="2" w:author="Omar Siddiqui" w:date="2026-01-01T00:00:00Z"><w:r>'
            f'<w:delText xml:space="preserve">{escape(text)}</w:delText></w:r></w:del>')


def para(*runs: str) -> str:
    return "<w:p>" + "".join(runs) + "</w:p>"


def wrap_document(body_xml: str, root_tag: str = "w:document") -> str:
    return (f'{XML_DECL}<{root_tag} xmlns:w="{W_NS}" xmlns:mc="{MC_NS}" '
            f'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<w:body>{body_xml}</w:body></{root_tag}>")


def comments_xml(comments: list[tuple[str, str]]) -> str:
    items = "".join(
        f'<w:comment w:id="{i}" w:author="{escape(a)}" w:date="2026-01-01T00:00:00Z">'
        f"<w:p>{run(t)}</w:p></w:comment>" for i, (a, t) in enumerate(comments))
    return f'{XML_DECL}<w:comments xmlns:w="{W_NS}">{items}</w:comments>'


def core_xml(creator: str, last_modified_by: str = "", title: str = "") -> str:
    return (f'{XML_DECL}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            f"<dc:title>{escape(title)}</dc:title><dc:creator>{escape(creator)}</dc:creator>"
            f"<cp:lastModifiedBy>{escape(last_modified_by)}</cp:lastModifiedBy></cp:coreProperties>")


def app_xml(company: str) -> str:
    return (f'{XML_DECL}<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f"<Company>{escape(company)}</Company><Application>Synthetic Writer</Application></Properties>")


def rels_xml(external: list[str] = ()) -> str:
    rels = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        f'Target="{escape(t)}" TargetMode="External"/>' for i, t in enumerate(external, start=10))
    return (f'{XML_DECL}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>')


def make_docx(body_xml: str, *, comments: list[tuple[str, str]] | None = None, core: str | None = None,
              app: str | None = None, external_links: list[str] = (), main_ct: str = DOCX_MAIN_CT,
              extra_parts: dict[str, bytes] | None = None, document_xml: str | None = None,
              header_xml: str | None = None) -> bytes:
    """Minimal OOXML package, built by zipping parts."""
    overrides = [f'<Override PartName="/word/document.xml" ContentType="{main_ct}"/>']
    parts: dict[str, str | bytes] = {
        "_rels/.rels": rels_xml(),
        "word/document.xml": document_xml if document_xml is not None else wrap_document(body_xml),
    }
    if external_links:
        parts["word/_rels/document.xml.rels"] = rels_xml(list(external_links))
    if comments is not None:
        parts["word/comments.xml"] = comments_xml(comments)
    if core is not None:
        parts["docProps/core.xml"] = core
    if app is not None:
        parts["docProps/app.xml"] = app
    if header_xml is not None:
        parts["word/header1.xml"] = wrap_document(header_xml, "w:hdr").replace("<w:body>", "").replace("</w:body>", "")
    parts.update(extra_parts or {})
    ct = (f'{XML_DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          f'<Default Extension="xml" ContentType="application/xml"/>{"".join(overrides)}</Types>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        for name, content in parts.items():
            z.writestr(name, content)
    return buf.getvalue()


# ------------------------------------------------------------------ PDF (built with pypdf)
def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(pages: list[list[str]], *, info: dict[str, str] | None = None, xmp: str | None = None,
             image_on_page: int | None = None, annotation_text: str | None = None, open_action_js: bool = False,
             encrypt_with: str | None = None) -> bytes:
    """Born-digital PDF: each page is a list of text lines in Helvetica. `image_on_page` (0-based) adds a
    1x1 image XObject (a stand-in for a logo or a scan). An empty page list entry gives a blank page."""
    from pypdf import PdfWriter
    from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject, NameObject, NumberObject,
                               TextStringObject)

    w = PdfWriter()
    font = w._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica")}))
    for idx, lines in enumerate(pages):
        page = w.add_blank_page(612, 792)
        resources = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        ops = ""
        if lines:
            ops += "BT /F1 12 Tf 72 720 Td 14 TL " + " T* ".join(f"({_pdf_escape(l)}) Tj" for l in lines) + " ET\n"
        if image_on_page == idx:
            img = DecodedStreamObject()
            img.set_data(b"\xff")
            img.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Image"),
                        NameObject("/Width"): NumberObject(1), NameObject("/Height"): NumberObject(1),
                        NameObject("/ColorSpace"): NameObject("/DeviceGray"),
                        NameObject("/BitsPerComponent"): NumberObject(8)})
            resources[NameObject("/XObject")] = DictionaryObject({NameObject("/Im0"): w._add_object(img)})
            ops += "q 100 0 0 100 50 50 cm /Im0 Do Q\n"
        page[NameObject("/Resources")] = resources
        stream = DecodedStreamObject()
        stream.set_data(ops.encode("latin-1"))
        page[NameObject("/Contents")] = w._add_object(stream)
        if idx == 0 and annotation_text:
            annot = DictionaryObject({
                NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Text"),
                NameObject("/Rect"): ArrayObject([NumberObject(0), NumberObject(0), NumberObject(10), NumberObject(10)]),
                NameObject("/Contents"): TextStringObject(annotation_text)})
            page[NameObject("/Annots")] = ArrayObject([w._add_object(annot)])
    if info:
        w.add_metadata({f"/{k}": v for k, v in info.items()})
    if xmp:
        meta = DecodedStreamObject()
        meta.set_data(xmp.encode("utf-8"))
        meta.update({NameObject("/Type"): NameObject("/Metadata"), NameObject("/Subtype"): NameObject("/XML")})
        w._root_object[NameObject("/Metadata")] = w._add_object(meta)
    if open_action_js:
        w._root_object[NameObject("/OpenAction")] = DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject("app.alert(1)")})
    if encrypt_with:
        w.encrypt(encrypt_with, algorithm="RC4-128")
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def xmp_packet(creator: str, tool: str = "Synthetic Writer") -> str:
    return ('<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" '
            f'xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="{escape(tool)}">'
            f"<dc:creator><rdf:Seq><rdf:li>{escape(creator)}</rdf:li></rdf:Seq></dc:creator>"
            "</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>")
