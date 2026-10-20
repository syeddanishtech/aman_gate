/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#070b16",
          900: "#0b1220",
          850: "#0e1627",
          800: "#121c30",
          700: "#1b2942",
          600: "#26395c",
        },
        allow: { DEFAULT: "#2dd4bf", dim: "#14908a" },
        approve: { DEFAULT: "#f5a623", dim: "#b97b12" },
        deny: { DEFAULT: "#f0506e", dim: "#b23651" },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
