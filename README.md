# StrainVault

StrainVault is a mobile-first cannabis journal for privately tracking strains, sessions, effects, stash, receipts, and personalized strain insights.

## GitHub Pages deploy

This version is a static PWA. It does not require Netlify, a backend, npm, a database, analytics, or exposed API keys.

Required root files:

- `index.html`
- `styles.css`
- `app.js`
- `manifest.webmanifest`
- `icon.svg`
- `.nojekyll`

## Setup

1. Upload these files directly into the root of the GitHub repository.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Choose branch: `main`.
5. Choose folder: `/ (root)`.
6. Save.

Your app will publish at a GitHub Pages URL such as:

`https://YOUR_USERNAME.github.io/YOUR_REPOSITORY_NAME/`

## Privacy

StrainVault stores data locally in the browser using local storage/IndexedDB-style browser storage. Do not put personal logs, receipts, or private keys directly into the GitHub repository.

## Notes

For GitHub Free, GitHub Pages is available for public repositories. Private repository Pages support depends on paid GitHub plans.

## Version 2 fix notes

- Fixed the empty-photo upload bug that could stop Save/Apply from working when no label or receipt image was selected.
- Added a dedicated Add/Edit Strain flow.
- Added Edit buttons for strain cards, journal sessions, and stash items.
- Added cache-busting query strings for `app.js` and `styles.css` so GitHub Pages refreshes the new build more reliably.


## Version 3 notes

- Added scanner-assisted strain entry: label photo + local text parsing fills strain name, brand, product type, THC/CBD, terpenes, and notes.
- Added an Apply to Strain Form button so scanned label details can prefill the full Add/Edit Strain form before saving.
- Turned the vault into a shareable strain-card library. Each strain now has a Share card button that renders a PNG card.
- Added Web Share API support where available, with Download PNG fallback.

Note: the scanner stays local-first and does not use external OCR APIs or exposed API keys. On iPhone/iPad, use the label photo plus iOS Live Text/copy-paste when automatic photo OCR is unavailable.


## Version 3.1 audit/fix notes

- Hardened optional photo handling so an unsupported image format cannot block saving strain, session, or stash text details.
- Fixed scanner text parsing for simple one-line labels like `Blue Dream, Flower, THC 24.6%, CBD 0.2%`.
- Preserved scanner label photos when using **Apply to Strain Form**.
- Improved **Log session** from a strain card so it prefills brand, type, THC/CBD, and terpenes from the saved strain card.
- Added cache-busting query strings for GitHub Pages refresh reliability.
