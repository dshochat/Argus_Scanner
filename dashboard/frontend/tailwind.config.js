/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          0: "#0a0d14", // page background
          1: "#111726", // cards
          2: "#171f31", // elevated / hover
          3: "#1f2940", // input / chips
        },
        line: "#222c41",
        brand: {
          DEFAULT: "#6ea8fe",
          dim: "#3b6fd4",
          soft: "#1b2c4d",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.02)",
      },
    },
  },
  plugins: [],
};
