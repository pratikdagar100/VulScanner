/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // VulScanner palette: deep navy chrome with severity accents.
        ink: { 950: '#070c14', 900: '#0b1220', 850: '#101a2c', 800: '#152238', 700: '#1d3050', 600: '#274469' },
        brand: { 50: '#eef6fd', 100: '#d6e9fa', 300: '#7cb8ee', 400: '#4b9ae6', 500: '#2481d8', 600: '#1766b4', 700: '#12518f' },
        severity: {
          critical: '#f0356b', high: '#fb7333', medium: '#f5c518', low: '#3ba3f5', info: '#8ba0b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['Cascadia Mono', 'Consolas', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        panel: '0 1px 2px rgba(4,10,20,.4), 0 8px 24px -12px rgba(4,10,20,.6)',
      },
    },
  },
  plugins: [],
};
