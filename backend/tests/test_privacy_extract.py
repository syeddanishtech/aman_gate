"""Local extraction: txt / born-digital PDF / DOCX, hidden-content detection, and the fail-closed
REVIEW_REQUIRED paths (scanned PDF, images, macros, DTDs, mismatches). Fixtures are built in memory."""
from __future__ import annotations

import io
import zipfile

import pytest
from privacy_fixtures import (
    DOCM_MAIN_CT,
    app_xml,
    core_xml,
    dele,
    ins,
    make_docx,
    make_pdf,
    para,
    run,
    wrap_document,
    xmp_packet,
)

from app.privacy.extract import (
    MAX_INPUT_BYTES,
    STATUS_OK,
    STATUS_REVIEW_REQUIRED,
    extract_docx,
    extract_document,
    extract_pdf,
    extract_text_bytes,
)


def kinds(doc):
    return {s.locator: s.kind for s in doc.segments}


def seg(doc, locator):
    return next(s.text for s in doc.segments if s.locator == locator)


def assert_review(doc, *reasons):
    assert doc.status == STATUS_REVIEW_REQUIRED and doc.review_required
    assert doc.segments == ()  # nothing partial is handed on
    for r in reasons:
        assert r in doc.review_reasons, (r, doc.review_reasons)


# ------------------------------------------------------------------ plain text
def test_txt_extracts_and_normalizes_newlines():
    doc = extract_document(b"line one\r\nline two\rline three\n", "note.txt")
    assert doc.status == STATUS_OK and doc.media_type == "text/plain"
    assert doc.body_text == "line one\nline two\nline three\n"
    assert doc.source_sha256 and doc.review_reasons == ()


def test_txt_utf8_bom_and_unicode_are_handled():
    doc = extract_text_bytes("﻿مصنوعی ذہانت café".encode("utf-8"))
    assert doc.status == STATUS_OK and doc.body_text == "مصنوعی ذہانت café"


@pytest.mark.parametrize("data,reason", [
    (b"abc\x00def", "BINARY_CONTENT"),
    (b"\xff\xfeh\x00i\x00", "BINARY_CONTENT"),  # UTF-16 is not guessed at
    (b"caf\xe9", "TEXT_DECODE_ERROR"),
    (b"bell\x07here", "CONTROL_CHARACTERS"),
])
def test_txt_uncertain_inputs_need_review(data, reason):
    assert_review(extract_text_bytes(data), reason)


def test_oversized_input_needs_review():
    assert_review(extract_text_bytes(b"a" * (MAX_INPUT_BYTES + 1)), "INPUT_TOO_LARGE")


# ------------------------------------------------------------------ born-digital PDF
def test_pdf_text_metadata_xmp_and_annotations_are_extracted():
    pdf = make_pdf([["Quote for Ayesha Khan", "Total: PKR 7,280,000"], ["Page two body"]],
                   info={"Author": "Fatima Raza", "Title": "Quote"}, xmp=xmp_packet("Omar Siddiqui"),
                   annotation_text="reviewer note: Sana Malik")
    doc = extract_document(pdf, "quote.pdf")
    assert doc.status == STATUS_OK and doc.media_type == "application/pdf"
    assert seg(doc, "pdf:page:1") == "Quote for Ayesha Khan\nTotal: PKR 7,280,000"
    assert seg(doc, "pdf:page:2") == "Page two body"
    assert "Fatima Raza" in seg(doc, "pdf:metadata:info")
    assert "Omar Siddiqui" in seg(doc, "pdf:metadata:xmp") and "Synthetic Writer" in seg(doc, "pdf:metadata:xmp")
    assert "Sana Malik" in seg(doc, "pdf:annotations")
    assert kinds(doc)["pdf:page:1"] == "body" and kinds(doc)["pdf:metadata:xmp"] == "metadata"
    assert doc.features["pages"] == 2 and doc.features["xmp_present"] is True and not doc.features["images_present"]
    assert doc.body_text == "Quote for Ayesha Khan\nTotal: PKR 7,280,000\n\nPage two body"


def test_scanned_pdf_blank_page_stub_is_review_required():
    doc = extract_document(make_pdf([[]]), "scan.pdf")
    assert_review(doc, "PDF_NO_EXTRACTABLE_TEXT")


def test_scanned_pdf_image_only_page_is_review_required_and_images_flagged():
    doc = extract_document(make_pdf([[]], image_on_page=0), "scan.pdf")
    assert_review(doc, "PDF_NO_EXTRACTABLE_TEXT", "PDF_IMAGES_UNREVIEWED")
    assert doc.features["images_present"] is True and doc.features["pages_without_text"] == 1


def test_pdf_with_text_but_an_embedded_image_is_blocked_not_guessed():
    doc = extract_document(make_pdf([["Letterhead text"]], image_on_page=0), "logo.pdf")
    assert_review(doc, "PDF_IMAGES_UNREVIEWED")  # logo / OCR review is Phase 2


def test_pdf_with_one_blank_page_among_text_pages_needs_review():
    doc = extract_document(make_pdf([["page one text"], [], ["page three text"]]), "gap.pdf")
    assert_review(doc, "PDF_PAGE_WITHOUT_TEXT")


def test_pdf_active_content_encryption_and_garbage_need_review():
    assert_review(extract_document(make_pdf([["x"]], open_action_js=True), "a.pdf"), "PDF_ACTIVE_CONTENT")
    assert_review(extract_document(make_pdf([["x"]], encrypt_with="pw"), "a.pdf"), "PDF_ENCRYPTED")
    assert_review(extract_document(b"%PDF-1.4 this is not really a pdf", "a.pdf"), "PDF_PARSE_ERROR")
    assert_review(extract_pdf(b""), "PDF_PARSE_ERROR")


def test_pdf_xmp_with_a_dtd_is_rejected():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
    assert_review(extract_document(make_pdf([["x"]], xmp=evil), "a.pdf"), "XML_DTD_REJECTED")


# ------------------------------------------------------------------ DOCX
def test_docx_body_comments_metadata_links_are_separated():
    docx = make_docx(
        para(run("Quote for Ayesha Khan. ")) + para(run("Total PKR 7,280,000")),
        comments=[("Bilal Ahmed", "ceiling is PKR 7,100,000")],
        core=core_xml("Zara Lodhi", "Fatima Raza", "Quote 101"), app=app_xml("Northbridge University"),
        external_links=["https://example.test/portal?u=ayesha"])
    doc = extract_document(docx, "quote.docx")
    assert doc.status == STATUS_OK and doc.media_type.endswith("wordprocessingml.document")
    assert seg(doc, "docx:word/document.xml") == "Quote for Ayesha Khan. \nTotal PKR 7,280,000"
    assert seg(doc, "docx:comments") == "Bilal Ahmed: ceiling is PKR 7,100,000"
    assert "Zara Lodhi" in seg(doc, "docx:docProps/core.xml") and "Fatima Raza" in seg(doc, "docx:docProps/core.xml")
    assert "Northbridge University" in seg(doc, "docx:docProps/app.xml")
    assert "example.test/portal" in seg(doc, "docx:links")
    assert kinds(doc)["docx:word/document.xml"] == "body"
    assert {k for l, k in kinds(doc).items() if l != "docx:word/document.xml"} == {"comments", "metadata", "links"}
    assert doc.features["comments"] == 1 and doc.features["metadata_fields"] == 5


def test_docx_tracked_changes_and_hidden_text_are_detected_and_kept_out_of_the_body():
    body = para(run("Visible start. "), ins("Inserted words. "), dele("Deleted secret ceiling PKR 7,100,000. "),
                run("Hidden aside", vanish=True), run(" visible end."))
    doc = extract_document(make_docx(body), "tc.docx")
    assert doc.status == STATUS_OK
    assert seg(doc, "docx:word/document.xml") == "Visible start. Inserted words.  visible end."  # accept-all view
    assert seg(doc, "docx:tracked_deletions") == "Deleted secret ceiling PKR 7,100,000."
    assert seg(doc, "docx:hidden_text") == "Hidden aside"
    assert doc.features["tracked_changes"] is True and doc.features["hidden_text"] is True
    assert kinds(doc)["docx:tracked_deletions"] == "tracked_deletions" and kinds(doc)["docx:hidden_text"] == "hidden_text"
    assert "Deleted secret" not in doc.body_text and "Hidden aside" not in doc.body_text


def test_docx_vanish_val_false_is_not_hidden():
    xml = '<w:p><w:r><w:rPr><w:vanish w:val="0"/></w:rPr><w:t>shown</w:t></w:r></w:p>'
    doc = extract_document(make_docx(xml), "v.docx")
    assert doc.body_text == "shown" and not doc.features["hidden_text"]


def test_docx_field_codes_are_captured_not_shown():
    xml = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> HYPERLINK "https://example.test/s" '
           '</w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>click here</w:t></w:r>'
           '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    doc = extract_document(make_docx(xml), "f.docx")
    assert doc.body_text == "click here" and "HYPERLINK" in seg(doc, "docx:field_codes")
    assert doc.features["field_codes"] is True


def test_docx_header_is_extracted_as_body():
    doc = extract_document(make_docx(para(run("main")), header_xml=para(run("Confidential header"))), "h.docx")
    assert doc.status == STATUS_OK and seg(doc, "docx:word/header1.xml") == "Confidential header"
    assert doc.body_text == "main\n\nConfidential header"  # package parts are read in sorted name order


@pytest.mark.parametrize("label,kwargs,reason", [
    ("image media part", dict(extra_parts={"word/media/image1.png": b"\x89PNG..."}), "GRAPHIC_CONTENT_UNREVIEWED"),
    ("thumbnail", dict(extra_parts={"docProps/thumbnail.jpeg": b"\xff\xd8"}), "GRAPHIC_CONTENT_UNREVIEWED"),
    ("embedded object", dict(extra_parts={"word/embeddings/oleObject1.bin": b"OLE"}), "GRAPHIC_CONTENT_UNREVIEWED"),
    ("vba macros", dict(extra_parts={"word/vbaProject.bin": b"VBA"}), "MACROS_PRESENT"),
    ("macro-enabled content type", dict(main_ct=DOCM_MAIN_CT), "NOT_A_DOCX"),
    ("unknown part", dict(extra_parts={"word/glossary/document.xml": b"<x/>"}), "UNPARSED_PARTS"),
])
def test_docx_images_macros_and_unknown_parts_need_review(label, kwargs, reason):
    assert_review(extract_document(make_docx(para(run("text")), **kwargs), "x.docx"), reason)


@pytest.mark.parametrize("snippet", ["<w:drawing><w:inline/></w:drawing>", "<w:pict/>", "<w:object/>"])
def test_docx_inline_drawing_needs_review(snippet):
    xml = f"<w:p><w:r><w:t>caption</w:t>{snippet}</w:r></w:p>"
    assert_review(extract_document(make_docx(xml), "d.docx"), "GRAPHIC_CONTENT_UNREVIEWED")


def test_docx_alternate_content_uses_only_the_first_choice():
    xml = ('<w:p><mc:AlternateContent><mc:Choice><w:r><w:t>modern</w:t></w:r></mc:Choice>'
           '<mc:Fallback><w:r><w:t>legacy duplicate</w:t></w:r></mc:Fallback></mc:AlternateContent></w:p>')
    assert extract_document(make_docx(xml), "a.docx").body_text == "modern"


def test_docx_dtd_entities_are_rejected():
    evil = ('<?xml version="1.0"?><!DOCTYPE w [<!ENTITY a "boom">]><w:document '
            f'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p></w:body></w:document>')
    assert_review(extract_document(make_docx("", document_xml=evil), "e.docx"), "XML_DTD_REJECTED")


def test_docx_malformed_and_non_docx_zip_need_review():
    assert_review(extract_document(make_docx("", document_xml="<w:document"), "m.docx"), "XML_PARSE_ERROR")
    assert_review(extract_docx(b"PK\x03\x04 not really a zip"), "NOT_A_VALID_ZIP")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml", "<x/>")
    assert_review(extract_document(buf.getvalue(), "sheet.docx"), "NOT_A_DOCX")


def test_docx_zip_hazards_need_review():
    def build(names):
        base = make_docx(para(run("ok")))
        out = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(base)) as src, zipfile.ZipFile(out, "w") as dst:
            for n in src.namelist():
                dst.writestr(n, src.read(n))
            for n in names:
                dst.writestr(n, b"x")
        return out.getvalue()

    assert_review(extract_docx(build(["../evil.xml"])), "UNSAFE_PART_NAME")
    assert_review(extract_docx(build(["/abs.xml"])), "UNSAFE_PART_NAME")
    with pytest.warns(UserWarning):  # zipfile warns about the duplicate name it is about to write
        dup = build(["word/document.xml"])
    assert_review(extract_docx(dup), "DUPLICATE_PART_NAME")


# ------------------------------------------------------------------ dispatcher
def test_type_is_decided_by_content_and_cross_checked_against_extension():
    assert_review(extract_document(make_pdf([["x"]]), "fake.txt"), "TYPE_MISMATCH")
    assert_review(extract_document(b"plain text", "fake.pdf"), "TYPE_MISMATCH")
    assert_review(extract_document(make_docx(para(run("x"))), "fake.pdf"), "TYPE_MISMATCH")
    assert_review(extract_document(b"hello", "photo.png"), "UNSUPPORTED_TYPE")
    assert_review(extract_document(b"hello", "legacy.doc"), "UNSUPPORTED_TYPE")
    assert_review(extract_document("not bytes", "a.txt"), "NOT_BYTES")  # type: ignore[arg-type]
    assert extract_document(b"no filename needed").status == STATUS_OK
    assert extract_document(make_pdf([["x"]])).media_type == "application/pdf"  # sniffed without a name
    assert extract_document(b"hi", "DIR\\NOTE.TXT").status == STATUS_OK  # case and Windows separators


def test_review_records_carry_codes_only_never_content():
    doc = extract_document(make_docx(para(run("Ayesha Khan")), extra_parts={"word/media/i.png": b"x"}), "x.docx")
    rec = doc.to_record()
    assert rec["status"] == STATUS_REVIEW_REQUIRED and rec["review_reasons"] == ["GRAPHIC_CONTENT_UNREVIEWED"]
    assert "Ayesha" not in str(rec)


def test_extraction_is_deterministic():
    docx = make_docx(para(run("same")), core=core_xml("A"))
    a, b = extract_document(docx, "x.docx"), extract_document(docx, "x.docx")
    assert a == b and a.source_sha256 == b.source_sha256
    assert wrap_document("") != ""  # fixture sanity
