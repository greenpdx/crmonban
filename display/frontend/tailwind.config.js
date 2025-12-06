/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts}'],
  theme: {
    extend: {
      colors: {
        dark: {
          50: '#f8fafc',
          100: '#1e293b',
          200: '#1a2332',
          300: '#151c28',
          400: '#111827',
          500: '#0d1219',
          600: '#0a0e14',
          700: '#070a0f',
          800: '#05070a',
          900: '#020304'
        },
        accent: {
          blue: '#3b82f6',
          green: '#22c55e',
          yellow: '#eab308',
          red: '#ef4444',
          purple: '#a855f7'
        }
      },
      spacing: {
        '0.5': '2px',
        '1': '4px',
        '1.5': '6px',
        '2': '8px',
        '3': '12px',
        '4': '16px'
      }
    }
  },
  plugins: []
}
