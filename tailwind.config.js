/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#111111',
        paper: '#f5f5f5',
        line: '#d4d4d4',
        muted: '#666666'
      },
      boxShadow: {
        soft: '0 1px 0 rgba(17, 17, 17, 0.06)'
      }
    }
  },
  plugins: []
};
