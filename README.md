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
