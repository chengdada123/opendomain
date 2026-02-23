/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      typography: {
        DEFAULT: {
          css: {
            '--tw-prose-body': 'var(--bc)',
            '--tw-prose-headings': 'var(--bc)',
            '--tw-prose-lead': 'var(--bc)',
            '--tw-prose-links': 'var(--p)',
            '--tw-prose-bold': 'var(--bc)',
            '--tw-prose-counters': 'var(--bc)',
            '--tw-prose-bullets': 'var(--bc)',
            '--tw-prose-hr': 'var(--b3)',
            '--tw-prose-quotes': 'var(--bc)',
            '--tw-prose-quote-borders': 'var(--p)',
            '--tw-prose-captions': 'var(--bc)',
            '--tw-prose-code': 'var(--bc)',
            '--tw-prose-pre-code': 'var(--bc)',
            '--tw-prose-pre-bg': 'var(--b2)',
            '--tw-prose-th-borders': 'var(--b3)',
            '--tw-prose-td-borders': 'var(--b3)',
          },
        },
      },
    },
  },
  plugins: [require("daisyui"), require("@tailwindcss/typography")],
  daisyui: {
    themes: ["light", "dark", "cupcake"],
    darkTheme: "dark",
    base: true,
    styled: true,
    utils: true,
    prefix: "",
    logs: true,
    themeRoot: ":root",
  },
}
