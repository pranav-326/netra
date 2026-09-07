/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          50: '#f0f5ff',
          100: '#e5edff',
          200: '#cddbfe',
          300: '#b4c6fc',
          400: '#8da2fb',
          500: '#6875f5',
          600: '#4852e6',
          700: '#3438cd',
          800: '#2327a3',
          900: '#1e217d',
          navy: '#0b132b',
        },
        slate: {
          850: '#151e2e',
          950: '#070b14',
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04)',
        'card': '0 4px 14px 0 rgba(0, 0, 0, 0.05)',
        'glow-blue': '0 0 20px -3px rgba(37, 99, 235, 0.25)',
        'glow-red': '0 0 20px -3px rgba(220, 38, 38, 0.25)',
      }
    },
  },
  plugins: [],
};
