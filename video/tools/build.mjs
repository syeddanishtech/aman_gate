// Builds every text deliverable from video/source/script.json (the single source of truth).
// Usage: node video/tools/build.mjs            -> writes video/out/* and video/animatic/data.js
// Exits non-zero if any timing / readability gate fails.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const S = JSON.parse(readFileSync(join(ROOT, "source", "script.json"), "utf8"));
const OUT = join(ROOT, "out");
mkdirSync(OUT, { recursive: true });

const MAX_LINE = 42;      // chars per subtitle line
const MAX_CPS = 17;       // reading speed ceiling (chars/sec)
const MIN_CUE = 1.2;      // seconds
const MIN_SUPER = 2.0;    // security events must stay readable >= 2.0 s
const WPM_RANGE = [130, 170];

const errors = [];
const warns = [];
const fmtTc = (t) => {
  const ms = Math.round(t * 1000);
  const h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000), r = ms % 1000;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")},${String(r).padStart(3, "0")}`;
};
const fmtMS = (t) => `${String(Math.floor(t / 60)).padStart(2, "0")}:${(t % 60).toFixed(1).padStart(4, "0")}`;
const frames = (t) => Math.round(t * S.fps);
const words = (t) => t.trim().split(/\s+/).filter(Boolean).length;

// Balanced split into <= 2 lines of <= MAX_LINE chars.
function wrap(text) {
  if (text.length <= MAX_LINE) return [text];
  const w = text.split(" ");
  let best = null;
  for (let i = 1; i < w.length; i++) {
    const a = w.slice(0, i).join(" "), b = w.slice(i).join(" ");
    if (a.length > MAX_LINE || b.length > MAX_LINE) continue;
    const score = Math.abs(a.length - b.length) + (/[,:.]$/.test(a) ? -6 : 0);
    if (!best || score < best.score) best = { lines: [a, b], score };
  }
  if (!best) { errors.push(`Cue cannot fit two lines of ${MAX_LINE}: "${text}"`); return [text]; }
  return best.lines;
}

// ---------------------------------------------------------------- validate
const end = S.segments.at(-1).out;
if (end > S.hard_limit_seconds) errors.push(`Timeline ${end}s exceeds hard limit ${S.hard_limit_seconds}s`);
if (Math.abs(end - S.target_seconds) > 0.001) warns.push(`Timeline ends at ${end}s, target ${S.target_seconds}s`);

let prevOut = 0, prevCueOut = 0, n = 0;
const cues = [];
for (const seg of S.segments) {
  if (Math.abs(seg.in - prevOut) > 0.001) errors.push(`Gap/overlap before segment ${seg.id}: ${prevOut} -> ${seg.in}`);
  prevOut = seg.out;
  for (const c of seg.cues) {
    n++;
    const dur = c.out - c.in, chars = c.text.length, cps = chars / dur;
    if (c.in < seg.in || c.out > seg.out) errors.push(`Cue ${n} outside segment ${seg.id}`);
    if (c.in < prevCueOut) errors.push(`Cue ${n} overlaps previous cue`);
    if (dur < MIN_CUE) errors.push(`Cue ${n} shorter than ${MIN_CUE}s`);
    if (cps > MAX_CPS) errors.push(`Cue ${n} reads at ${cps.toFixed(1)} cps (> ${MAX_CPS}): "${c.text}"`);
    prevCueOut = c.out;
    cues.push({ n, seg: seg.id, ...c, dur, chars, cps, words: words(c.text), lines: wrap(c.text) });
  }
  for (const sp of seg.supers) {
    const dur = sp.out - sp.in;
    if (["allow", "deny", "approve"].includes(sp.style) && dur < MIN_SUPER)
      errors.push(`Security super "${sp.text}" visible only ${dur.toFixed(2)}s (< ${MIN_SUPER}s)`);
    if (sp.in < seg.in - 0.001 || sp.out > seg.out + 0.001) errors.push(`Super "${sp.text}" outside segment ${seg.id}`);
  }
}
for (const sh of S.shots) {
  const seg = S.segments.find((s) => s.id === sh.seg);
  if (!seg || sh.in < seg.in - 0.001 || sh.out > seg.out + 0.001) errors.push(`Shot ${sh.id} outside segment ${sh.seg}`);
}

const totalWords = cues.reduce((a, c) => a + c.words, 0);
const speechSecs = cues.reduce((a, c) => a + c.dur, 0);
const wpmSpoken = (totalWords / speechSecs) * 60;
if (wpmSpoken < WPM_RANGE[0] || wpmSpoken > WPM_RANGE[1])
  warns.push(`Spoken rate ${wpmSpoken.toFixed(0)} wpm outside ${WPM_RANGE.join("-")}`);

// ---------------------------------------------------------------- SRT
const srt = cues.map((c) => `${c.n}\n${fmtTc(c.in)} --> ${fmtTc(c.out)}\n${c.lines.join("\n")}\n`).join("\n");
writeFileSync(join(OUT, "aman_gate_en.srt"), srt, "utf8");

// ---------------------------------------------------------------- VO script (for the voice artist)
let vo = `AMAN GATE — VOICEOVER SCRIPT ${S.version}\n` +
  `Read calm, plain, credible. ~150 wpm inside each line; breathe in the gaps.\n` +
  `Pronounce: AMAN = "ah-MAHN" (Urdu: safety). ACL = "A-C-L". Prompt injection = two words, even stress.\n` +
  `Total words: ${totalWords}. Speaking time: ${speechSecs.toFixed(1)} s. Spoken rate: ${wpmSpoken.toFixed(0)} wpm.\n` +
  `Timecodes are the TARGET slot for each line. Record each line as its own take; editor places it.\n\n`;
for (const seg of S.segments) {
  vo += `── ${seg.n}. ${seg.title.toUpperCase()}  [${fmtMS(seg.in)}–${fmtMS(seg.out)}]\n`;
  for (const c of cues.filter((x) => x.seg === seg.id))
    vo += `  VO${String(c.n).padStart(2, "0")}  ${fmtMS(c.in)}  (${c.dur.toFixed(1)} s)  ${c.text}\n`;
  vo += "\n";
}
writeFileSync(join(OUT, "aman_gate_vo_script.txt"), vo, "utf8");
writeFileSync(join(OUT, "aman_gate_vo_lines.json"),
  JSON.stringify(cues.map((c) => ({ id: `VO${String(c.n).padStart(2, "0")}`, in: c.in, out: c.out, text: c.text })), null, 1));

// ---------------------------------------------------------------- timeline CSV (editor EDL-style)
const q = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
const rows = [["track", "id", "segment", "in_tc", "out_tc", "in_frame", "out_frame", "dur_s", "source", "content"].join(",")];
for (const seg of S.segments) {
  rows.push(["V1", `SEG${seg.n}`, seg.id, fmtTc(seg.in), fmtTc(seg.out), frames(seg.in), frames(seg.out),
    (seg.out - seg.in).toFixed(2), seg.source, q(seg.visual)].join(","));
  for (const sh of S.shots.filter((x) => x.seg === seg.id))
    rows.push(["V2", sh.id, seg.id, fmtTc(sh.in), fmtTc(sh.out), frames(sh.in), frames(sh.out),
      (sh.out - sh.in).toFixed(2), sh.optional ? "capture (optional)" : "capture (REAL)", q(`${sh.view} — ${sh.action}`)].join(","));
  for (const sp of seg.supers)
    rows.push(["V3", "SUPER", seg.id, fmtTc(sp.in), fmtTc(sp.out), frames(sp.in), frames(sp.out),
      (sp.out - sp.in).toFixed(2), `text/${sp.style}`, q(sp.text)].join(","));
  for (const c of cues.filter((x) => x.seg === seg.id))
    rows.push(["A1", `VO${String(c.n).padStart(2, "0")}`, seg.id, fmtTc(c.in), fmtTc(c.out), frames(c.in), frames(c.out),
      c.dur.toFixed(2), "voiceover", q(c.text)].join(","));
  rows.push(["A2", "MUSIC", seg.id, fmtTc(seg.in), fmtTc(seg.out), frames(seg.in), frames(seg.out),
    (seg.out - seg.in).toFixed(2), "music bed", q(seg.music)].join(","));
}
writeFileSync(join(OUT, "aman_gate_timeline.csv"), rows.join("\n") + "\n", "utf8");

// ---------------------------------------------------------------- animatic data
mkdirSync(join(ROOT, "animatic"), { recursive: true });
writeFileSync(join(ROOT, "animatic", "data.js"),
  `// Generated by video/tools/build.mjs — do not edit by hand.\nwindow.AMAN_SCRIPT = ${JSON.stringify({ ...S, cues })};\n`, "utf8");

// ---------------------------------------------------------------- report
const report = [
  `AMAN Gate video build check — ${new Date().toISOString()}`,
  `Timeline: ${end.toFixed(2)} s (${frames(end)} frames @ ${S.fps} fps); limit ${S.hard_limit_seconds} s; margin ${(S.hard_limit_seconds - end).toFixed(1)} s`,
  `Segments: ${S.segments.length}; VO cues: ${cues.length}; shots: ${S.shots.length} (${S.shots.filter((s) => !s.optional).length} required)`,
  `VO: ${totalWords} words, ${speechSecs.toFixed(1)} s of speech, ${wpmSpoken.toFixed(0)} wpm spoken, ${((totalWords / end) * 60).toFixed(0)} wpm over whole film`,
  `Max cps: ${Math.max(...cues.map((c) => c.cps)).toFixed(1)} (limit ${MAX_CPS}); max line: ${Math.max(...cues.flatMap((c) => c.lines.map((l) => l.length)))} chars (limit ${MAX_LINE})`,
  "",
  ...S.segments.map((s) => `  ${s.n}. ${s.title.padEnd(44)} ${fmtMS(s.in)}–${fmtMS(s.out)}  ${(s.out - s.in).toFixed(1).padStart(4)} s  ${s.source}`),
  "",
  errors.length ? `ERRORS (${errors.length}):\n  - ${errors.join("\n  - ")}` : "ERRORS: none",
  warns.length ? `WARNINGS (${warns.length}):\n  - ${warns.join("\n  - ")}` : "WARNINGS: none",
].join("\n");
writeFileSync(join(OUT, "build_check.txt"), report + "\n", "utf8");
console.log(report);
process.exit(errors.length ? 1 : 0);
