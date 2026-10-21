// SIMULATION ONLY. Everything in this file stands in for backend endpoints that do not exist yet
// (Privacy Shield / Safe Cloud Bridge / Output Assurance). The UI tags every value that came from here
// as MOCK and shows the global "Simulation" watermark. Nothing here is a security control.
//
// The detector is a small deterministic regex pass over text the REAL gateway already returned
// (api.readDocument) — so highlighted spans are genuine substrings of the genuine document — but the
// *detections, actions and "safe copy"* are produced in the browser, not by the AMAN privacy backend.
import type {
  AnalyzeResponse,
  ArtifactResponse,
  AssuranceResponse,
  BridgeSendResponse,
  DisclosureElement,
  Finding,
  ProviderMode,
} from "./api";

export const SAMPLE_DOC_ID = "SAMPLE-INVOICE";
export const SAMPLE_TEXT = `NORTHBRIDGE UNIVERSITY - SUPPLIER INVOICE (SYNTHETIC SAMPLE)
Invoice: INV-2026-0412
Contact: Ahmed Raza
Email: ahmed.raza@supplier.example
Phone: +92 300 1234567
CNIC: 35202-1234567-1
Bank: PK36SCBL0000001123456702
Total due: PKR 4,250,000 for 12 laboratory workstations.
Internal note: negotiation ceiling LAB-CANARY-7731 - do not disclose to the supplier.
`;

interface Rule {
  type: string;
  re: RegExp;
  sensitivity: string;
  action: "pseudonymize" | "redact" | "omit" | "generalize";
  label?: string; // placeholder stem for pseudonymize / redact
}

// Order matters: earlier rules win overlapping spans.
const RULES: Rule[] = [
  { type: "canary_token", re: /LAB-CANARY-\d+/g, sensitivity: "restricted", action: "omit" },
  { type: "bank_account", re: /\bPK\d{2}[A-Z]{4}\d{16}\b/g, sensitivity: "restricted", action: "redact", label: "ACCOUNT" },
  { type: "national_id", re: /\b\d{5}-\d{7}-\d\b/g, sensitivity: "restricted", action: "redact", label: "ID" },
  { type: "email", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, sensitivity: "confidential", action: "pseudonymize", label: "EMAIL" },
  { type: "phone", re: /(?:\+92[ -]?|\b0)3\d{2}[ -]?\d{7}\b/g, sensitivity: "confidential", action: "pseudonymize", label: "PHONE" },
  {
    type: "person_name",
    re: /(?<=\b(?:Contact|Attn|Attention|Name|Prepared by|Signed by|Sales Rep)[ \t]*:[ \t]*)[A-Z][a-z]+(?:[ ][A-Z][a-z]+){1,2}/g,
    sensitivity: "confidential",
    action: "pseudonymize",
    label: "PERSON",
  },
  { type: "monetary_amount", re: /PKR\s?(?:\d{1,3}(?:,\d{3})+|\d{5,})/g, sensitivity: "confidential", action: "generalize" },
  { type: "institution_name", re: /Northbridge University(?: \(fictional\))?/gi, sensitivity: "internal", action: "generalize" },
];

function amountBand(raw: string): string {
  const n = Number(raw.replace(/[^\d]/g, ""));
  if (n < 100_000) return "under PKR 100K";
  if (n < 1_000_000) return "PKR 100K-1M";
  if (n < 10_000_000) return "PKR 1M-10M";
  return "over PKR 10M";
}

interface Hit {
  start: number;
  end: number;
  rule: Rule;
  original: string;
}

function detect(text: string): Hit[] {
  const hits: Hit[] = [];
  for (const rule of RULES) {
    for (const m of text.matchAll(new RegExp(rule.re.source, rule.re.flags))) {
      if (m.index == null) continue;
      hits.push({ start: m.index, end: m.index + m[0].length, rule, original: m[0] });
    }
  }
  hits.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: Hit[] = [];
  let cursor = -1;
  for (const h of hits) {
    if (h.start >= cursor) {
      kept.push(h);
      cursor = h.end;
    }
  }
  return kept;
}

interface Stored extends ArtifactResponse {
  docId: string;
  blocked: boolean;
  reason?: string;
  vault: Record<string, string>; // placeholder -> original (stays in this browser tab; mock of the local vault)
}

const store = new Map<string, Stored>();
let lastArtifactId: string | null = null;
let counter = 0;

function build(docId: string, text: string, opts: { restricted?: boolean; reason?: string }): { id: string; stored: Stored } {
  const hits = detect(text);
  const counts = new Map<string, number>();
  const pseudo = new Map<string, string>();
  const vault: Record<string, string> = {};
  const findings: Finding[] = [];
  let safe = "";
  let at = 0;
  hits.forEach((h, i) => {
    let replacement: string;
    const { rule } = h;
    if (rule.action === "omit") replacement = "[REMOVED]";
    else if (rule.action === "redact") replacement = `[REDACTED_${rule.label}]`;
    else if (rule.action === "generalize")
      replacement = rule.type === "monetary_amount" ? amountBand(h.original) : "[INSTITUTION]";
    else {
      const key = `${rule.type}:${h.original.toLowerCase()}`;
      let ph = pseudo.get(key);
      if (!ph) {
        const n = (counts.get(rule.type) ?? 0) + 1;
        counts.set(rule.type, n);
        ph = `[${rule.label}_${n}]`;
        pseudo.set(key, ph);
        vault[ph] = h.original;
      }
      replacement = ph;
    }
    findings.push({
      id: `F${i + 1}`,
      type: rule.type,
      page: 1,
      sensitivity: rule.sensitivity,
      action: rule.action,
      start: h.start,
      end: h.end,
      original: h.original,
      replacement,
    });
    safe += text.slice(at, h.start) + replacement;
    at = h.end;
  });
  safe += text.slice(at);

  const blocked = !!opts.restricted;
  counter += 1;
  const id = `mock-artifact-${String(counter).padStart(3, "0")}`;
  const stored: Stored = {
    docId,
    blocked,
    reason: opts.reason,
    original_preview: text,
    safe_copy_preview: blocked ? "" : safe,
    findings,
    vault,
  };
  store.set(id, stored);
  lastArtifactId = id;
  return { id, stored };
}

/** MOCK of POST /api/privacy/analyze. `doc` is what the REAL gateway returned for the document. */
export function analyze(
  documentId: string,
  doc: { text?: string; denied?: any; meta?: any },
): AnalyzeResponse {
  if (doc.denied || doc.text == null) {
    const reason = doc.denied?.message || doc.denied?.code || "gateway denied access";
    const { id } = build(documentId, "", { restricted: true, reason });
    return {
      disclosure: { elements: [], findings_count: 0 },
      safe_artifact_id: id,
      decision: "BLOCKED",
      blocked_reason: `Access denied by the gateway: ${reason}`,
    };
  }
  const restricted = doc.meta?.classification === "restricted";
  const { id, stored } = build(documentId, doc.text, {
    restricted,
    reason: restricted ? "Restricted classification may not leave the device." : undefined,
  });
  const trust = doc.meta?.trust_label ?? "unknown";
  const elements: DisclosureElement[] = stored.findings.map((f, i) => ({
    id: `E${i + 1}`,
    type: f.type,
    page: f.page ?? 1,
    sensitivity: f.sensitivity ?? "internal",
    source_trust: trust,
    action: restricted ? "deny" : f.action ?? "redact",
  }));
  return {
    disclosure: { elements, findings_count: elements.length },
    safe_artifact_id: id,
    decision: restricted ? "BLOCKED" : "READY_FOR_REVIEW",
    ...(restricted ? { blocked_reason: "Restricted classification may not leave the device." } : {}),
  };
}

/** MOCK of GET /api/privacy/artifacts/{id}. */
export function artifact(artifactId: string): ArtifactResponse {
  const s = store.get(artifactId);
  if (!s) {
    const err: any = new Error("mock artifact store is per-session memory; artifact not found");
    err.status = 404;
    throw err;
  }
  return { original_preview: s.original_preview, safe_copy_preview: s.safe_copy_preview, findings: s.findings };
}

let sampleCache: { id: string; art: ArtifactResponse } | null = null;

/** The built-in labelled sample used by the Overview before any document is analyzed (built once). */
export function sampleArtifact(): ArtifactResponse {
  if (!sampleCache) {
    const previous = lastArtifactId;
    const { id, stored } = build(SAMPLE_DOC_ID, SAMPLE_TEXT, {});
    sampleCache = {
      id,
      art: { original_preview: stored.original_preview, safe_copy_preview: stored.safe_copy_preview, findings: stored.findings },
    };
    // Building the sample must not hijack "the most recent artifact" used as the assurance reference.
    lastArtifactId = previous ?? id;
  }
  return sampleCache.art;
}

const PLACEHOLDER_RE = /\[[A-Z]+_\d+\]/g;

/** MOCK of POST /api/bridge/send — a deterministic canned "assistant" built from the safe copy only. */
export function bridgeSend(artifactId: string, mode: ProviderMode): BridgeSendResponse {
  const s = store.get(artifactId);
  if (!s) {
    const err: any = new Error("mock artifact store is per-session memory; artifact not found");
    err.status = 404;
    throw err;
  }
  const lines = s.safe_copy_preview.split("\n").map((l) => l.trim()).filter(Boolean);
  const headline = (lines[0] ?? "(empty document)").slice(0, 120);
  const ph = Array.from(new Set(s.safe_copy_preview.match(PLACEHOLDER_RE) ?? []));
  const contact = ph.find((p) => p.startsWith("[PERSON")) ?? ph.find((p) => p.startsWith("[EMAIL"));
  const body = [
    "[SIMULATED RESPONSE - LOCAL_SIMULATOR - no model was called, nothing left this machine]",
    `Summary: this looks like a business document headed "${headline}".`,
    ph.length ? `It references these protected entities: ${ph.join(", ")}.` : "It references no protected entities.",
    contact ? `Suggested next step: confirm details with ${contact} through the approved channel.` : "Suggested next step: route to the document owner for review.",
  ].join("\n");
  const reasons: string[] = [];
  if (mode === "REAL_CLOUD") reasons.push("EGRESS_DEFAULT_DENY", "REAL_CLOUD_NOT_ENABLED");
  if (mode === "LOCAL_LLM") reasons.push("LOCAL_LLM_NOT_CONFIGURED");
  return {
    mode: "LOCAL_SIMULATOR",
    response: body,
    watermark: true,
    ...(reasons.length ? { egress_blocked_reasons: reasons } : {}),
  };
}

/** MOCK of POST /api/assurance/check. Uses the most recently analyzed artifact as the reference. */
export function assuranceCheck(response: string): AssuranceResponse {
  const ref = (lastArtifactId && store.get(lastArtifactId)) || null;
  const expected = Array.from(new Set(ref?.safe_copy_preview.match(PLACEHOLDER_RE) ?? []));
  const found = Array.from(new Set(response.match(PLACEHOLDER_RE) ?? []));
  const unexpected = found.filter((p) => !expected.includes(p));
  const dropped = expected.filter((p) => !found.includes(p));
  const malformed = Array.from(response.matchAll(/\[(?:EMAIL|PHONE|PERSON)[ -]\d+\]|\b(?:EMAIL|PHONE|PERSON)_\d+\b(?!\])/g)).map((m) => m[0]);
  const ok = unexpected.length === 0 && malformed.length === 0;

  const leaks: { type: string; severity: string; excerpt: string; reason: string }[] = [];
  const seen = new Set<string>();
  const mask = (v: string) => (v.length <= 4 ? "****" : v.slice(0, 2) + "***" + v.slice(-2));
  for (const f of ref?.findings ?? []) {
    if (!f.original || f.action === "generalize") continue;
    if (response.toLowerCase().includes(f.original.toLowerCase()) && !seen.has(f.original)) {
      seen.add(f.original);
      leaks.push({ type: f.type, severity: "high", excerpt: mask(f.original), reason: "original value present in model output" });
    }
  }
  for (const h of detect(response)) {
    if (h.rule.action === "generalize" || seen.has(h.original)) continue;
    seen.add(h.original);
    leaks.push({ type: h.rule.type, severity: "high", excerpt: mask(h.original), reason: "sensitive pattern detected in model output" });
  }

  const flags: { code: string; message: string }[] = [];
  if (/https?:\/\//i.test(response)) flags.push({ code: "unexpected_url", message: "Response contains a link that is not in the safe copy." });
  if (/ignore (all )?(previous|prior) instructions/i.test(response))
    flags.push({ code: "instruction_echo", message: "Response repeats instruction-like text." });
  const safeNums = new Set(ref?.safe_copy_preview.match(/\d{4,}/g) ?? []);
  const loose = (response.match(/\d{4,}/g) ?? []).filter((n) => !safeNums.has(n));
  if (loose.length) flags.push({ code: "ungrounded_number", message: `Number(s) not present in the safe copy: ${Array.from(new Set(loose)).join(", ")}` });
  if (!response.trim()) flags.push({ code: "empty_response", message: "Response is empty." });

  let rehydrated = response;
  for (const [p, original] of Object.entries(ref?.vault ?? {})) rehydrated = rehydrated.split(p).join(original);
  return {
    placeholder_integrity: { ok, expected: expected.length, found: found.length, dropped, unexpected, malformed },
    leaks,
    flags,
    rehydrated,
  };
}
