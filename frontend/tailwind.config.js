/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0f1d',
          card: 'rgba(17, 24, 39, 0.7)',
          accent: '#06b6d4', // Cyan
          border: 'rgba(51, 65, 85, 0.6)',
          text: '#f1f5f9',
          success: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444'
        }
      },
      boxShadow: {
        'cyan-glow': '0 0 15px rgba(6, 182, 212, 0.35)',
        'danger-glow': '0 0 15px rgba(239, 68, 68, 0.35)',
      }
    },
  },
  plugins: [],
}
