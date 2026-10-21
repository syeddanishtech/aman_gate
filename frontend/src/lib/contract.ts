// Defensive helpers for the PROVISIONAL privacy/bridge/assurance contract: the exact shape of several fields
// (decision strings, findings, placeholder_integrity, leaks, flags) is not fixed yet, so the UI reads them
// through these functions instead of assuming a shape.
import type { ArtifactResponse, Finding } from "../api";

export type Decision = "NOT_SHARED" | "READY_FOR_REVIEW" | "BLOCKED" | "APPROVED";

export const DECISION_LABEL: Record<Decision, string> = {
  NOT_SHARED: "NOT SHARED",
  READY_FOR_REVIEW: "READY FOR REVIEW",
  BLOCKED: "BLOCKED",
  APPROVED: "APPROVED",
};

/** Map whatever the backend sends in `decision` onto the four UI states. Unknown values fail SAFE (review). */
export function normalizeDecision(raw: string | undefined | null): Decision {
  const d = String(raw ?? "").toUpperCase().replace(/[\s-]+/g, "_");
  if (!d) return "NOT_SHARED";
  if (/(BLOCK|DENY|DENIED|REFUS|REJECT)/.test(d)) return "BLOCKED";
  if (d === "APPROVED") return "APPROVED";
  if (/NOT_SHARED/.test(d)) return "NOT_SHARED";
  return "READY_FOR_REVIEW"; // READY_FOR_REVIEW | NEEDS_APPROVAL | ALLOW | anything else -> human review
}

export interface Range {
  start: number;
  end: number;
  index: number; // index into findings (0-based)
  finding: Finding;
}

/** Locate each finding inside `text`. Original side prefers start/end offsets, else the literal original;
 *  safe side searches for the literal replacement, walking forward so repeated placeholders map in order. */
export function locate(text: string, findings: Finding[], side: "original" | "safe"): Range[] {
  const out: Range[] = [];
  const overlaps = (s: number, e: number) => out.some((r) => s < r.end && e > r.start);
  let cursor = 0;
  findings.forEach((f, index) => {
    let span: [number, number] | null = null;
    if (side === "original" && typeof f.start === "number" && typeof f.end === "number" && f.end > f.start) {
      span = [f.start, f.end];
    } else {
      const needle = side === "original" ? f.original : f.replacement;
      if (needle) {
        let at = text.indexOf(needle, cursor);
        if (at < 0) {
          at = 0;
          while ((at = text.indexOf(needle, at)) >= 0 && overlaps(at, at + needle.length)) at += 1;
        }
        if (at >= 0) span = [at, at + needle.length];
      }
    }
    if (span && span[1] <= text.length && !overlaps(span[0], span[1])) {
      out.push({ start: span[0], end: span[1], index, finding: f });
      cursor = span[1];
    }
  });
  return out.sort((a, b) => a.start - b.start);
}

export interface Check {
  label: string;
  ok: boolean | null; // null = not applicable / cannot be checked from the data given
  detail: string;
}

function originalOf(f: Finding, art: ArtifactResponse): string | undefined {
  if (f.original) return f.original;
  if (typeof f.start === "number" && typeof f.end === "number") return art.original_preview.slice(f.start, f.end);
  return undefined;
}

/** UI cross-check on the artifact the backend (or mock) returned. This is NOT the backend's independent
 *  second-extractor verification (that result is not part of the provisional contract) — it only re-scans
 *  the safe-copy PREVIEW we were given. */
export function verifySafeCopy(art: ArtifactResponse): Check[] {
  const safe = art.safe_copy_preview ?? "";
  const lowered = safe.toLowerCase();
  const checks: Check[] = [];

  const withOriginal = art.findings
    .map((f) => ({ f, o: originalOf(f, art) }))
    .filter((x): x is { f: Finding; o: string } => !!x.o && x.f.action !== "keep" && x.f.action !== "generalize");
  const survivors = withOriginal.filter((x) => lowered.includes(x.o.toLowerCase()));
  const nothingToRescan = art.findings.length === 0
    ? "no findings, so nothing to remove"
    : art.findings.every((f) => f.action === "generalize" || f.action === "keep")
    ? "only generalized values (no exact originals to look for)"
    : "findings carry no original text to compare";
  checks.push(
    withOriginal.length
      ? {
          label: "No original sensitive value appears in the safe copy",
          ok: survivors.length === 0,
          detail:
            survivors.length === 0
              ? `${withOriginal.length} value(s) re-scanned, 0 survive`
              : `${survivors.length} of ${withOriginal.length} value(s) still present`,
        }
      : { label: "No original sensitive value appears in the safe copy", ok: null, detail: nothingToRescan },
  );

  const withRepl = art.findings.filter((f) => f.replacement);
  const missing = withRepl.filter((f) => !safe.includes(f.replacement as string));
  checks.push(
    withRepl.length
      ? {
          label: "Every finding was replaced by a placeholder",
          ok: missing.length === 0,
          detail: missing.length === 0 ? `${withRepl.length} replacement(s) located` : `${missing.length} replacement(s) not located`,
        }
      : { label: "Every finding was replaced by a placeholder", ok: null, detail: "findings carry no replacement text" },
  );

  checks.push({
    label: "Safe copy differs from the original",
    ok: safe.length > 0 && safe !== art.original_preview,
    detail: safe.length === 0 ? "safe copy is empty" : safe === art.original_preview ? "identical to original" : "content was transformed",
  });
  return checks;
}

export interface Integrity {
  ok: boolean | null;
  rows: [string, string][];
}

/** `placeholder_integrity` may be a boolean, a status string, or an object — render all of them sensibly. */
export function readIntegrity(pi: unknown): Integrity {
  if (typeof pi === "boolean") return { ok: pi, rows: [] };
  if (typeof pi === "string") {
    const good = /^(ok|pass|passed|valid|intact|true)$/i.test(pi.trim());
    const bad = /^(fail|failed|invalid|broken|false)$/i.test(pi.trim());
    return { ok: good ? true : bad ? false : null, rows: [["status", pi]] };
  }
  if (pi && typeof pi === "object") {
    const o = pi as Record<string, unknown>;
    const rows: [string, string][] = Object.entries(o)
      .filter(([k]) => k !== "ok")
      .map(([k, v]) => [k.replace(/_/g, " "), Array.isArray(v) ? (v.length ? v.map(describeItem).join(", ") : "none") : String(v)]);
    const ok = typeof o.ok === "boolean" ? o.ok : typeof o.valid === "boolean" ? o.valid : typeof o.passed === "boolean" ? o.passed : null;
    return { ok, rows };
  }
  return { ok: null, rows: [] };
}

export function describeItem(x: unknown): string {
  if (x == null) return "";
  if (typeof x === "string" || typeof x === "number" || typeof x === "boolean") return String(x);
  const o = x as Record<string, unknown>;
  const head = (o.type ?? o.code ?? o.kind ?? o.id) as string | undefined;
  const tail = (o.reason ?? o.message ?? o.detail ?? o.excerpt) as string | undefined;
  if (head && tail) return `${head} — ${tail}`;
  return head ?? tail ?? JSON.stringify(x);
}

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
