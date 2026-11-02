# Reopening the corporate and account logins

Three steps, in order. Steps 1 and 2 need your Firebase credentials — Vercel
does not deploy `functions/` or `firestore.rules`, so they are still live in
their old form until you run them.

## 1. Deploy the functions and the rules

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE" && firebase deploy --only functions,firestore:rules
```

This is scoped — it does not touch hosting. It deploys:

| Function | Change |
| --- | --- |
| `corporateLogin` | returns the account id with "no password set" |
| `resetCorpPassword` | stores a bcrypt hash, deletes the plaintext field |
| `corporateSetTempPassword` | **new** — admin temp password, hashed |
| `migrateCorporatePasswords` | **new** — one-time migration, step 2 |

`firebase deploy` validates `firestore.rules` before applying and refuses a bad
file, so a syntax error cannot reach production.

## 2. Run the migration once

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE" && firebase functions:shell --only migrateCorporatePasswords
```

Then at the prompt:

```
migrateCorporatePasswords({confirm:'MIGRATE'})
```

It hashes every remaining plaintext password into `corporate_auth` and deletes
the field from `corporate_accounts`. **Check that the result says
`remaining: 0`.** Nobody is locked out — existing passwords keep working,
they are just stored as hashes from then on.

## 3. Reopen the logins

Remove these six lines from `vercel.json`, then commit and push:

```json
{ "source": "/account",               "destination": "/secure-access", "permanent": false },
{ "source": "/account.html",          "destination": "/secure-access", "permanent": false },
{ "source": "/corporate",             "destination": "/secure-access", "permanent": false },
{ "source": "/corporate.html",        "destination": "/secure-access", "permanent": false },
{ "source": "/corporate-portal",      "destination": "/secure-access", "permanent": false },
{ "source": "/corporate-portal.html", "destination": "/secure-access", "permanent": false }
```

`/corporate-portal` has to come back too — corporate sign-in redirects there,
so reopening `/corporate` alone would bounce people straight to
`/secure-access` after a successful login.

Leave `/driver-portal`, `/admin`, `/schedule` and `/payment` paused.

## Then check

- Sign in at `/corporate` with a real account — it should reach the portal.
- A wrong password should say "Incorrect email/phone or password."
- In the Firebase console, open any `corporate_accounts` document and confirm
  there is no `password` field.

## Still open

- **`clients` passwords are plaintext too**, and `clients` is world-readable.
  `account.html` (lines ~1743, ~3416, ~3444), `corporate-portal.html`
  (~3228, ~3269) and `admin.html` (~3630) all write them. This is the same
  exposure as the corporate one and needs the same treatment.
- **The rest of the Firestore rules are still `allow read, write: if true`**
  for `bookings`, `clients`, `trips`, `invoices`, `estimates` and
  `admin_settings`. Anyone can read or modify them.
- **The Google Maps API key** in `schedule.html` and `account.html` needs an
  HTTP-referrer restriction in Google Cloud Console, or usage can be billed to
  you by anyone who copies it.
