/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#14120f',
        panel: '#1c1a16',
        panel2: '#232019',
        line: 'rgba(255,255,255,0.08)',
        brass: '#e8a33d',
        brassdim: '#8a5f22',
        sage: '#4caf7d',
        rust: '#d4573e',
        fog: '#a8a29a',
      },
      fontFamily: {
        sans: ['"Segoe UI Variable"', '"Segoe UI"', 'system-ui', 'sans-serif'],
        display: ['Georgia', '"Times New Roman"', 'serif'],
        mono: ['"Cascadia Mono"', 'Consolas', '"Courier New"', 'monospace'],
      },
    },
  },
  plugins: [],
}
