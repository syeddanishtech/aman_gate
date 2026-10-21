/** @type {import('tailwindcss').Config} */
// AMAN Gate 2.0 design system (LIGHT theme).
//
// The 1.0 components were written against a dark palette (navy-* surfaces, slate-* text). To re-theme
// them without rewriting their logic, those token names are KEPT and re-pointed at light values:
//   navy-*   -> light surfaces / hairline borders      slate-* -> navy-ink text ramp (all >= 4.5:1 on white)
//   allow    -> the ONE electric teal #087F8C          approve -> warning amber #D97706
//   deny     -> deny red #C0363D
// `*-ink` variants are the AA-safe text colours of each accent (raw amber/teal on a tint fails 4.5:1).
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0F233F",
        page: "#F7F9FC",
        navy: {
          950: "#EDF1F7",
          900: "#F4F7FB",
          850: "#FFFFFF",
          800: "#EAEFF5",
          700: "#D3DBE7",
          600: "#B4C0D1",
        },
        slate: {
          100: "#0F233F",
          200: "#1E3350",
          300: "#34475F",
          400: "#475A72",
          500: "#52657D",
          600: "#5A6C84",
          700: "#5A6C84",
        },
        allow: { DEFAULT: "#087F8C", dim: "#066570", ink: "#066570" },
        approve: { DEFAULT: "#D97706", dim: "#B45309", ink: "#8F4506" },
        deny: { DEFAULT: "#C0363D", dim: "#A92E35", ink: "#A92E35" },
      },
      fontFamily: {
        sans: ['"Inter Variable"', "Inter", '"Segoe UI"', "system-ui", "sans-serif"],
        mono: ["Consolas", '"SF Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(15, 35, 63, 0.06), 0 1px 3px rgba(15, 35, 63, 0.05)",
        lift: "0 4px 12px rgba(15, 35, 63, 0.08), 0 1px 3px rgba(15, 35, 63, 0.06)",
      },
    },
  },
  plugins: [],
};
