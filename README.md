# Lumen — private photo galleries

Upload photos, set a password, pick what visitors may do, and send one private link.
Black / white / gold design, works on phones and computers, **no paid services, no credit card**.

- **3 access modes per gallery:** View only · View & download · Full access (changeable any time)
- **Password-protected links** (hashed with scrypt), optional expiry date, instant **revoke**, or **new link**
- **Owner dashboard:** upload with progress and previews, rename / replace / delete photos, storage meter, access activity
- **Zero dependencies:** nothing to `npm install`. Just Node.js 22.5 or newer.

---

## The free setup (≈ 20 minutes, one time)

| Part | Service | Free allowance | Card needed? |
|---|---|---|---|
| Photos | **Backblaze B2** | 10 GB storage | No ¹ |
| Database | **Turso** | 5 GB | No ¹ |
| Website | **Render** (free web service) | 750 hrs / month | No ¹ |

That is well above your 2 GB target. The app stops uploads at `STORAGE_LIMIT_GB` (default **9.5** on Render) so you can never drift past Backblaze's free 10 GB by accident.

¹ These are the providers' published terms when this was written (October 2026). I could not create accounts for you, and providers change their plans, so glance at each pricing page when you sign up. Cloudflare R2 was rejected because it requires a payment method on file.

### Step 1 · Photo storage (Backblaze B2)
1. Create an account at backblaze.com and open **B2 Cloud Storage**.
2. **Create a bucket.** Name it anything. Set it to **Private** (important).
3. On the bucket page, copy the **Endpoint**, e.g. `s3.us-west-004.backblazeb2.com`.
4. Go to **Application Keys → Add a New Application Key**. Allow access to your bucket only, with read & write. Copy the **keyID** and **applicationKey** straight away (the key is shown only once).

You do **not** need to set up CORS or make anything public. Photos are only ever delivered through the app after the password check.

### Step 2 · Database (Turso)
1. Create an account at turso.tech and **create a database** (any name, nearest region).
2. Copy its **URL** (starts with `libsql://`).
3. Create a **token** for that database and copy it.

### Step 3 · Put the code on GitHub
Create a **private** repository on github.com and upload everything in this folder (drag and drop works on the repo page). The `.gitignore` already keeps secrets and local data out.

### Step 4 · Deploy on Render
1. At render.com choose **New → Blueprint** and select your repository. Render reads `render.yaml` for you.
2. When asked, fill in these values (all come from the steps above):

| Name | Value |
|---|---|
| `OWNER_PASSWORD` | A long passphrase **you** invent. This is your dashboard login. |
| `S3_ENDPOINT` | `https://` + the endpoint from Step 1, e.g. `https://s3.us-west-004.backblazeb2.com` |
| `S3_BUCKET` | Your bucket name |
| `S3_KEY_ID` | The keyID |
| `S3_APP_KEY` | The applicationKey |
| `TURSO_URL` | The `libsql://…` URL |
| `TURSO_AUTH_TOKEN` | The Turso token |

3. Click **Apply**. After a couple of minutes Render shows your address (like `https://lumen-xxxx.onrender.com`).
4. Open it, click **Owner sign in**, and enter your `OWNER_PASSWORD`. Create a gallery, upload, share. 🎉

The dashboard shows a red warning bar if storage is not configured, and the storage meter names the backend in use (**Backblaze B2**), so you can confirm photos are going to permanent storage.

### Run it on your own computer instead
```
cp .env.example .env        # then edit OWNER_PASSWORD
node server.js              # open http://localhost:3000
```
With no `S3_*` / `TURSO_*` settings, photos and the database are saved in the `data/` folder next to the app.

---

## Honest limits of the free plans

- **Render free sleeps** after 15 minutes without visitors; the next visit takes ~30–60 seconds to wake. It also has monthly hour and bandwidth allowances. If exceeded, it pauses until the next month. Because all photos are delivered *through* the app (that is what keeps originals private), heavy sharing counts against Render's bandwidth.
- **Backblaze B2 free** includes 10 GB of storage and downloads up to 3× your stored amount per month, plus a daily allowance of free download requests (about 2,500). Every thumbnail or photo view is one request; the app caches thumbnails to help. Past the free allowances Backblaze would require a payment method, so a very busy gallery could be throttled rather than billed.
- **Turso free:** 5 GB, and monthly read/write allowances far beyond what this app uses.
- **Max photo size:** 25 MB each (`MAX_UPLOAD_MB`). ZIP downloads of a single gallery are limited to about 3.9 GB.
- Storage usage shown is what *this app* has stored (originals + thumbnails), not a reading from Backblaze's billing.

## What "View only" can and cannot do

**What it does:** requires the link (and password) first · no download buttons · images are only delivered to the gallery page itself, so opening an image address directly, hot-linking, or "open image in new tab" is refused · right-click, drag, copy, Save/Print shortcuts blocked · printing blocked · gallery hides when the window loses focus or the tab is hidden · optional on-screen watermark text · nothing cached for full-size images.

**What it cannot do:** **no website can prevent screenshots, screen recording, or someone photographing the screen with another phone.** Browsers give websites no way to switch that off. Treat View only as a strong deterrent for casual copying, not as a guarantee. For photos that must never leak, add a watermark and share lower-resolution proofs.

## Security notes
- Links contain 144 random bits (not guessable). Unknown, revoked and expired links return the same response.
- Gallery passwords are salted **scrypt** hashes. Passwords are rate-limited (6 wrong guesses per visitor per 15 minutes, plus a per-gallery cap). Owner sign-in is limited the same way. A determined attacker could still deliberately lock out visitors for 15 minutes by failing attempts; that is the trade-off for strong guess protection.
- Changing a password, rotating the link or revoking invalidates every existing visitor session immediately.
- Sessions use HttpOnly, SameSite=Strict, Secure cookies; strict Content-Security-Policy; `no-referrer`; `noindex` headers and `robots.txt` keep galleries out of search engines.
- Only real JPEG / PNG / WebP files are accepted (checked by file signature, not by name).
- **Access activity** records only counts and timestamps (opens, unlocks, wrong passwords, downloads). No IP addresses, devices or names are stored.
- Anyone who has the link *and* password can share them. Use **Create new link** if a link spreads further than intended.

## What was tested (`npm test`)
25 automated tests, all passing, covering: upload & display of JPEG/PNG/WebP · rejection of fake images · storage meter & quota · rename / replace / delete (and that files are really removed) · password gate with no data leaking before sign-in · hashed passwords · all three modes (view-only blocks downloads, ZIP and direct image URLs; download mode ZIP verified with `unzip -t`; full access) · changing modes live · revoke / restore / new link · expiry · brute-force lockouts · visitors unable to reach owner endpoints or raw files · restart persistence · S3 and Turso adapters against protocol mock servers · Backblaze/AWS request signing against Amazon's published test vectors.

**Not verified (please check on your first deploy):**
- I had no real Backblaze, Turso or Render accounts, so those three were tested against faithful local stand-ins and Amazon's official signing examples rather than the live services. If something is misconfigured the app fails loudly (a clear message in the dashboard or Render logs), never silently.
- The web pages were **not opened in a real browser or on a real phone** in my environment. They are built mobile-first (responsive CSS, touch swipe, 44 px tap targets) and their scripts are syntax-checked, but give the dashboard and a gallery link a quick look on your phone after deploying.

## Files
`server.js` app + API · `lib/` database, storage, signing, ZIP · `public/` pages and styles · `test/` tests · `render.yaml` one-click deploy · `.env.example` settings template
