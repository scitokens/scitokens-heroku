/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  // Scan the static site, including the class names built dynamically in the
  // inline <script> (signature/claim state classes, mobile-menu toggles).
  content: ['./public/**/*.html'],
  theme: { extend: {} },
  plugins: [],
};
