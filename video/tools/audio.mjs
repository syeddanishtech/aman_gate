// Audio deliverables, no external dependencies:
//   out/music_bed.wav      original synthesized soft-pulse bed, normalised to MUSIC_LUFS (BS.1770 integrated)
//   out/guide_vo.wav       scratch VO lines from out/guide_vo/*.wav placed at their cue times
//   out/guide_mix.wav      guide VO + music bed (timing reference for the animatic)
//   out/audio_check.txt    per-line fit report + loudness measurements
// Usage: node video/tools/audio.mjs
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "out");
const SR = 48000;
const T = 115.0;
const N = Math.round(SR * T);
const MUSIC_LUFS = -28;   // bed level as delivered; sits under VO without further gain
const VO_LUFS = -16;      // guide VO target (YouTube-friendly speech level)

// ---------------------------------------------------------------- WAV io (16-bit PCM)
function readWav(path) {
  const b = readFileSync(path);
  let p = 12, fmt = null, data = null;
  while (p < b.length - 8) {
    const id = b.toString("ascii", p, p + 4), sz = b.readUInt32LE(p + 4);
    if (id === "fmt ") fmt = { ch: b.readUInt16LE(p + 10), sr: b.readUInt32LE(p + 12), bits: b.readUInt16LE(p + 22) };
    if (id === "data") data = b.subarray(p + 8, p + 8 + sz);
    p += 8 + sz + (sz & 1);
  }
  if (!fmt || !data || fmt.bits !== 16) throw new Error(`Unsupported WAV ${path}`);
  const frames = data.length / 2 / fmt.ch, x = new Float32Array(frames);
  for (let i = 0; i < frames; i++) x[i] = data.readInt16LE(i * 2 * fmt.ch) / 32768; // first channel
  return { sr: fmt.sr, x };
}
function writeWav(path, L, R) {
  const frames = L.length, buf = Buffer.alloc(44 + frames * 4);
  buf.write("RIFF", 0); buf.writeUInt32LE(36 + frames * 4, 4); buf.write("WAVEfmt ", 8);
  buf.writeUInt32LE(16, 16); buf.writeUInt16LE(1, 20); buf.writeUInt16LE(2, 22); buf.writeUInt32LE(SR, 24);
  buf.writeUInt32LE(SR * 4, 28); buf.writeUInt16LE(4, 32); buf.writeUInt16LE(16, 34); buf.write("data", 36);
  buf.writeUInt32LE(frames * 4, 40);
  for (let i = 0; i < frames; i++) {
    buf.writeInt16LE(Math.max(-32768, Math.min(32767, Math.round(L[i] * 32767))), 44 + i * 4);
    buf.writeInt16LE(Math.max(-32768, Math.min(32767, Math.round(R[i] * 32767))), 46 + i * 4);
  }
  writeFileSync(path, buf);
}

// ---------------------------------------------------------------- BS.1770-4 integrated loudness (48 kHz)
function biquad(x, b, a) {
  const y = new Float32Array(x.length); let x1 = 0, x2 = 0, y1 = 0, y2 = 0;
  for (let i = 0; i < x.length; i++) {
    const v = b[0] * x[i] + b[1] * x1 + b[2] * x2 - a[1] * y1 - a[2] * y2;
    x2 = x1; x1 = x[i]; y2 = y1; y1 = v; y[i] = v;
  }
  return y;
}
const kw = (x) => biquad(
  biquad(x, [1.53512485958697, -2.69169618940638, 1.19839281085285], [1, -1.69065929318241, 0.73248077421585]),
  [1, -2, 1], [1, -1.99004745483398, 0.99007225036621]);
function lufs(chs) {
  const k = chs.map(kw), blk = Math.round(0.4 * SR), hop = Math.round(0.1 * SR), z = [];
  for (let s = 0; s + blk <= k[0].length; s += hop) {
    let sum = 0;
    for (const c of k) { let m = 0; for (let i = s; i < s + blk; i++) m += c[i] * c[i]; sum += m / blk; }
    z.push(sum);
  }
  const L = (ms) => -0.691 + 10 * Math.log10(ms);
  const abs = z.filter((v) => L(v) > -70);
  if (!abs.length) return -Infinity;
  const rel = L(abs.reduce((a, v) => a + v, 0) / abs.length) - 10;
  const g = abs.filter((v) => L(v) > rel);
  return L(g.reduce((a, v) => a + v, 0) / g.length);
}
const peakDb = (chs) => 20 * Math.log10(Math.max(...chs.map((c) => c.reduce((m, v) => Math.max(m, Math.abs(v)), 0))));

// ---------------------------------------------------------------- music bed (original composition)
const hz = (midi) => 440 * Math.pow(2, (midi - 69) / 12);
const BPM = 84, BEAT = 60 / BPM, CHORD_LEN = BEAT * 8;   // two bars per chord
// D minor: Dm - Bb - F - C ; final resolve to D major (Picardy third).
const PROG = [[50, 53, 57, 62], [46, 53, 58, 62], [53, 57, 60, 65], [48, 55, 60, 64]];
const RESOLVE = [50, 54, 57, 62, 66];
const RESOLVE_AT = 108.4;

function env(t, a, b, fade) { // raised-cosine window between a and b
  if (t < a - fade || t > b + fade) return 0;
  if (t < a + fade) return 0.5 - 0.5 * Math.cos(Math.PI * (t - (a - fade)) / (2 * fade));
  if (t > b - fade) return 0.5 - 0.5 * Math.cos(Math.PI * ((b + fade) - t) / (2 * fade));
  return 1;
}
const inRange = (t, a, b) => t >= a && t < b;

function music() {
  const L = new Float32Array(N), R = new Float32Array(N);
  const nChords = Math.ceil(RESOLVE_AT / CHORD_LEN);
  // Pad
  for (let c = 0; c <= nChords; c++) {
    const final = c === nChords;
    const a = final ? RESOLVE_AT : c * CHORD_LEN, b = final ? T : Math.min((c + 1) * CHORD_LEN, RESOLVE_AT);
    const notes = final ? RESOLVE : PROG[c % PROG.length];
    const s0 = Math.max(0, Math.floor((a - 1.2) * SR)), s1 = Math.min(N, Math.ceil((b + 1.2) * SR));
    notes.forEach((m, vi) => {
      const f = hz(m), dl = Math.pow(2, 3 / 1200), dr = Math.pow(2, -3 / 1200), pan = (vi / (notes.length - 1)) - 0.5;
      for (let i = s0; i < s1; i++) {
        const t = i / SR;
        let e = env(t, a, b, 1.1);
        if (final) e *= Math.exp(-Math.max(0, t - (RESOLVE_AT + 1.5)) / 2.2); // ring out
        if (!e) continue;
        const bright = inRange(t, 25, 39) || inRange(t, 98, 115) ? 0.22 : 0.12;
        const vl = Math.sin(2 * Math.PI * f * dl * t) + bright * Math.sin(4 * Math.PI * f * dl * t) + 0.05 * Math.sin(6 * Math.PI * f * t);
        const vr = Math.sin(2 * Math.PI * f * dr * t + 0.7) + bright * Math.sin(4 * Math.PI * f * dr * t) + 0.05 * Math.sin(6 * Math.PI * f * t);
        const breathe = 0.85 + 0.15 * Math.sin(2 * Math.PI * 0.07 * t + vi);
        L[i] += 0.06 * e * breathe * vl * (0.5 - pan * 0.4);
        R[i] += 0.06 * e * breathe * vr * (0.5 + pan * 0.4);
      }
    });
  }
  // Soft pulse (sub thump on each beat) from 10 s; ducked under the demo; stops at resolve.
  for (let k = 0; ; k++) {
    const tb = 10 + k * BEAT; if (tb >= RESOLVE_AT) break;
    const root = PROG[Math.floor(tb / CHORD_LEN) % PROG.length][0] - 12;
    const duck = inRange(tb, 58, 83) ? 0.79 : 1, accent = k % 4 === 0 ? 1 : 0.7;
    const s0 = Math.floor(tb * SR), len = Math.floor(0.45 * SR);
    for (let i = 0; i < len && s0 + i < N; i++) {
      const t = i / SR, f = hz(root) * (1 + 0.6 * Math.exp(-t / 0.02));
      const v = 0.16 * duck * accent * Math.exp(-t / 0.16) * Math.sin(2 * Math.PI * f * t) * Math.min(1, t / 0.004);
      L[s0 + i] += v; R[s0 + i] += v;
    }
  }
  // Pluck arpeggio over the reveal and the use-case/closing lift.
  for (const [a, b] of [[25.2, 39], [98.2, 108.4]]) {
    for (let k = 0; ; k++) {
      const tb = a + k * BEAT / 2; if (tb >= b) break;
      const chord = PROG[Math.floor(tb / CHORD_LEN) % PROG.length], m = chord[[0, 2, 1, 3, 2, 1][k % 6]] + 12;
      const s0 = Math.floor(tb * SR), len = Math.floor(0.6 * SR), pan = k % 2 ? 0.65 : 0.35;
      for (let i = 0; i < len && s0 + i < N; i++) {
        const t = i / SR, f = hz(m);
        const v = 0.035 * Math.exp(-t / 0.22) * (Math.sin(2 * Math.PI * f * t) + 0.3 * Math.sin(4 * Math.PI * f * t)) * Math.min(1, t / 0.003);
        L[s0 + i] += v * (1 - pan); R[s0 + i] += v * pan;
      }
    }
  }
  // Gentle one-pole low-pass for warmth + master fades.
  for (const ch of [L, R]) {
    let y = 0; const a = Math.exp(-2 * Math.PI * 5200 / SR);
    for (let i = 0; i < N; i++) {
      y = (1 - a) * ch[i] + a * y;
      const t = i / SR;
      ch[i] = y * Math.min(1, t / 1.5) * Math.min(1, (T - t) / 0.4);
    }
  }
  return [L, R];
}

// `measure` lets a mono signal be measured as dual-mono while the gain is applied once.
function gainTo(chs, target, measure = chs) {
  const cur = lufs(measure), g = Math.pow(10, (target - cur) / 20);
  for (const c of new Set(chs)) for (let i = 0; i < c.length; i++) c[i] *= g;
  return { before: cur, gain_db: 20 * Math.log10(g) };
}

// Sample-peak limiter: instant attack, 60 ms release, ceiling -1 dBFS. Scratch-quality only.
function limit(chs, ceilingDb = -1) {
  const ceil = Math.pow(10, ceilingDb / 20), rel = Math.exp(-1 / (0.06 * SR));
  let g = 1;
  for (let i = 0; i < chs[0].length; i++) {
    let pk = 0;
    for (const c of chs) pk = Math.max(pk, Math.abs(c[i]));
    const need = pk > ceil ? ceil / pk : 1;
    g = need < g ? need : 1 - (1 - g) * rel;
    for (const c of new Set(chs)) c[i] *= g;
  }
}

// ---------------------------------------------------------------- run
const report = [`AMAN Gate audio check — ${new Date().toISOString()}`];
const [mL, mR] = music();
const mg = gainTo([mL, mR], MUSIC_LUFS);
writeWav(join(OUT, "music_bed.wav"), mL, mR);
report.push(`music_bed.wav: original synthesis (D minor, ${BPM} bpm, resolves to D major at ${RESOLVE_AT}s)`,
  `  integrated ${lufs([mL, mR]).toFixed(1)} LUFS (target ${MUSIC_LUFS}), peak ${peakDb([mL, mR]).toFixed(1)} dBFS, length ${T.toFixed(2)} s`);

const lines = JSON.parse(readFileSync(join(OUT, "aman_gate_vo_lines.json"), "utf8"));
const vo = new Float32Array(N);
let overruns = 0;
report.push("", "Guide VO fit (Windows SAPI scratch voice; speech trimmed of leading/trailing silence):");
for (const l of lines) {
  const p = join(OUT, "guide_vo", `${l.id}.wav`);
  if (!existsSync(p)) { report.push(`  ${l.id} MISSING`); overruns++; continue; }
  const w = readWav(p);
  if (w.sr !== SR) throw new Error(`${p} is ${w.sr} Hz, expected ${SR}`);
  let a = 0, b = w.x.length - 1;
  while (a < b && Math.abs(w.x[a]) < 0.01) a++;
  while (b > a && Math.abs(w.x[b]) < 0.01) b--;
  const speech = (b - a + 1) / SR, slot = l.out - l.in, fit = speech <= slot + 0.05;
  if (!fit) overruns++;
  report.push(`  ${l.id} slot ${slot.toFixed(2)}s  speech ${speech.toFixed(2)}s  ${fit ? "fits" : "OVERRUN +" + (speech - slot).toFixed(2) + "s"}  ${l.text}`);
  const s0 = Math.round(l.in * SR);
  for (let i = a; i <= b && s0 + i - a < N; i++) vo[s0 + i - a] += w.x[i];
}
gainTo([vo], VO_LUFS, [vo, vo]);
limit([vo]);
writeWav(join(OUT, "guide_vo.wav"), vo, vo);
const mixL = new Float32Array(N), mixR = new Float32Array(N);
for (let i = 0; i < N; i++) { mixL[i] = vo[i] + mL[i]; mixR[i] = vo[i] + mR[i]; }
limit([mixL, mixR]);
writeWav(join(OUT, "guide_mix.wav"), mixL, mixR);
report.push("", `guide_vo.wav: ${lufs([vo, vo]).toFixed(1)} LUFS (mono measured as dual-mono), peak ${peakDb([vo]).toFixed(1)} dBFS`,
  `guide_mix.wav: ${lufs([mixL, mixR]).toFixed(1)} LUFS integrated, peak ${peakDb([mixL, mixR]).toFixed(1)} dBFS`,
  `VO-to-music gap: ${(VO_LUFS - MUSIC_LUFS).toFixed(0)} LU`, "", overruns ? `OVERRUNS: ${overruns}` : "OVERRUNS: none");
writeFileSync(join(OUT, "audio_check.txt"), report.join("\n") + "\n");
console.log(report.join("\n"));
process.exit(overruns ? 1 : 0);
