# StrainVault

## v3.8 Review Score Update

This build adds full 1–10 strain reviews for visual appearance, smell/aroma, taste/flavor, effects, and price/value. StrainVault now calculates an automatic overall review score, shows review breakdowns on strain cards and journal entries, and includes review scoring in shareable strain cards.


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

Note: the scanner stays local-first and does not use external OCR APIs or exposed API keys. v3.8 can load an open-source browser OCR library from a CDN when you tap **Read label photo**; the package image is processed in the browser. If the OCR library cannot load or cannot read the label, use iPhone/iPad Live Text to copy the label text and paste it into the app.


## Version 3.1 audit/fix notes

- Hardened optional photo handling so an unsupported image format cannot block saving strain, session, or stash text details.
- Fixed scanner text parsing for simple one-line labels like `Blue Dream, Flower, THC 24.6%, CBD 0.2%`.
- Preserved scanner label photos when using **Apply to Strain Form**.
- Improved **Log session** from a strain card so it prefills brand, type, THC/CBD, and terpenes from the saved strain card.
- Added cache-busting query strings for GitHub Pages refresh reliability.


## v3.2 Scanner Fix
- Adds Read label photo workflow with browser OCR fallback.
- Prevents empty photo uploads from creating Untitled strain drafts.
- Improves scanner status messages and strain-name parsing.

## v3.4 Missouri Label Capture Fix

- Runs multiple OCR passes: cropped white test label, high-contrast cannabinoid table, package/logo area, full photo, top brand area, and inverted fallback.
- Improves brand detection with common cannabis-brand matching and better `grown by / packaged by / manufactured by` parsing.
- Improves THC/CBD detection from cannabis lab-table formats, including `THCA`, `Δ9 THC`, `CBDA`, `Total THC`, `Total CBD`, and `Total Cannabinoids`.
- Calculates Total THC/CBD from acid forms when the label does not explicitly show totals.
- Shows missing scanner fields clearly so the user can correct only what OCR could not read.
- Updates GitHub Pages cache busting to `v=36`.


## v3.5 Missouri label scanner fix

This build improves the scanner review draft for cannabis package labels like the Show Biz example. It now captures and stores:

- strain name from the line after Marijuana Product Approval Number
- brand/grower or Produced By license code
- THC % and CBD % when exact potency values are readable
- Exact Potency mg/serving values
- terpene profile values
- Best if Used By date
- Produced By
- Testing License #
- Testing Tag #
- Source Tag #
- Total Weight and servings/doses
- Marijuana Product Approval Number
- usage/effect instructions when readable

The app now runs extra OCR passes over the label header, exact potency table, terpene table, and approval/strain-name area, then shows all captured fields for review before saving.


## v3.8 Scanner accuracy update

- Adds strict scanner review mode so weak OCR guesses are not saved as facts.
- Adds Paste copied Live Text support for higher-accuracy iPhone/iPad label text capture.
- Adds editable package label fields for best-used-by date, produced-by license, testing license, testing/source tags, total weight, approval number, exact potency table, terpene profile, and instructions.
- Saves corrected structured label facts with each strain card.


## v3.8 audited fix

- Hardened save/export encoding for larger local photo data.
- Preserved terpene text such as mg/serving without splitting it into bad library tags.
- Improved exact potency handling for Delta-9/D9-THC labels.
- Preserved manually corrected scanner THC/CBD values inside saved label facts.
- Re-ran static checks, parser tests, manifest validation, and zip integrity checks.
