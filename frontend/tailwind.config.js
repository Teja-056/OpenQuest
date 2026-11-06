/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        shield: {
          950: '#070608', // Deepest void obsidian black
          900: '#0d0a0e', // Dark carbon black
          850: '#140e15', // Gunmetal carbon
          800: '#1e131d', // Border carbon
          700: '#301826', // Muted dark ruby border
          600: '#492237', // Dark wine
          500: '#6d2e4d', // Dark rose
          accent: '#ef4444', // Neon Cyber Red
          cyan: '#f43f5e', // Cyber Rose-Red
          alert: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          info: '#e11d48',
          red: '#dc2626',
          crimson: '#e11d48',
          neon: '#ff1744',
        }
      },
      boxShadow: {
        'cyber-red': '0 0 25px rgba(239, 68, 68, 0.25)',
        'cyber-glow': '0 0 35px rgba(225, 29, 72, 0.35)',
      }
    },
  },
  plugins: [],
}
