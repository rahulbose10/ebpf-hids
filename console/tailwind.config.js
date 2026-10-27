/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],

  theme: {
    extend: {
      colors: {
        ink: "#0d1422",
        "ink-800": "#111a2b",
        "ink-700": "#16223a",
        "ink-600": "#1d2c49",

        line: "#243149",
        mute: "#7e8aa0",
        text: "#e6edf6",

        signal: "#4fd1c5",
        ml: "#7c8cf8",

        critical: "#ff5d5d",
        high: "#f2a65a",
        medium: "#e8c34a",
        low: "#39c2b0",
      },

      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        body: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },

      keyframes: {
        tapein: {
          "0%": {
            opacity: "0",
            transform: "translateY(8px)",
          },
          "100%": {
            opacity: "1",
            transform: "translateY(0)",
          },
        },

        pulse2: {
          "0%, 100%": {
            opacity: "1",
          },
          "50%": {
            opacity: "0.4",
          },
        },
      },

      animation: {
        tapein: "tapein 0.3s ease-out",
        pulse2: "pulse2 1.5s infinite",
      },
    },
  },

  plugins: [],
};