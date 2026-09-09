import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#0A0E14",
          surface: "#10141C",
          raised: "#161B26",
          border: "#212836"
        },
        ink: {
          DEFAULT: "#E7EBF2",
          muted: "#8A93A6",
          faint: "#5B6478"
        },
        trace: {
          DEFAULT: "#00D9C0",
          dim: "#0A6B60"
        },
        verdict: {
          phishing: "#F4415C",
          suspicious: "#F5A524",
          safe: "#22C55E"
        }
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'Inter'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"]
      },
      borderRadius: {
        DEFAULT: "6px"
      },
      backgroundImage: {
        grid: "linear-gradient(#212836 1px, transparent 1px), linear-gradient(90deg, #212836 1px, transparent 1px)"
      }
    }
  },
  plugins: []
};
export default config;
