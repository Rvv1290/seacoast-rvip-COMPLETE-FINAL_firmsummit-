# Reopening the corporate and account logins

Do these in order. Steps 1–3 need your Firebase credentials — Vercel does not
deploy `functions/` or `firestore.rules`, so both are still live in their old
form until you run them.

**Until step 1 is done, `/account` sign-in will not work** (it shows a generic
"Sign-in error" message rather than failing open). `/corporate` is unaffected,
because `corporateLogin` was already deployed. Both are still behind
`/secure-access`, so nobody is hitting them today.

## 1. Deploy the functions and the rules

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE" && firebase deploy --only functions,firestore:rules
```

Scoped — it does not touch hosting.

| Function | Change |
| --- | --- |
| `corporateLogin` | returns the account id with "no password set"; strips plaintext after migrating |
| `corporateSetCorporatePassword` | accepts a verified Firebase Auth session; sets `hasPassword` |
| `corporateSetTempPassword` | **new** — admin temp password, hashed, admin claim required |
| `migrateCorporatePasswords` | **new** — one-time migration, step 2 |
| `clientLogin` | **new** — personal-client sign-in, bcrypt against `client_auth` |
| `clientSetPassword` | **new** — hashed; current password or verified session required |
| `clientSetTempPassword` | **new** — admin temp password, admin claim required |
| `migrateClientPasswords` | **new** — one-time migration, step 2 |
| `resetCorpPassword` | stores a hash, deletes the plaintext field |

`firebase deploy` validates `firestore.rules` before applying and refuses a bad
file, so a syntax error cannot reach production.

## 2. Run both migrations once

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE" && firebase functions:shell
```

At the prompt:

```
migrateCorporatePasswords({confirm:'MIGRATE'})
migrateClientPasswords({confirm:'MIGRATE'})
```

Each hashes every remaining plaintext password into `corporate_auth` /
`client_auth` and deletes the field. **Check both results say `remaining: 0`.**
Nobody is locked out — existing passwords keep working, they are just stored as
hashes from then on.

## 3. Grant yourself the admin claim

The admin-only functions (`corporateSetTempPassword`, `clientSetTempPassword`)
require a Firebase Auth user with `admin: true`. Set it once, replacing the
email with the account you will sign in to admin.html with:

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE/functions" && node -e "const a=require('firebase-admin');a.initializeApp();a.auth().getUserByEmail(process.argv[1]).then(u=>a.auth().setCustomUserClaims(u.uid,{admin:true})).then(()=>console.log('admin claim set')).catch(e=>{console.error(e.message);process.exit(1)})" YOUR_ADMIN_EMAIL
```

**admin.html has no sign-in at all today** — no password, no Firebase Auth. Until
one is added, those two buttons (Approve Client, Portal Access) will return
"Administrator sign-in required." Everything else in admin still works. Keep
`/admin` paused until it has a real login; see "Still open" below.

## 4. Reopen the logins

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
- Sign in at `/account` with both a phone and an email account.
- A wrong password should say "Incorrect email/phone or password."
- Change a password from inside each portal — it now asks for the current one.
- In the Firebase console, open any `corporate_accounts` and any `clients`
  document and confirm there is no `password` field.

## Still open

- **admin.html has no authentication.** Anyone who reaches the URL gets full
  control of bookings, clients, drivers and corporate accounts. This is now the
  largest hole, and it is also what blocks the rest of the rules lockdown below.
  It needs a real sign-in (Firebase Auth email/password plus the `admin` claim
  from step 3) before `/admin` is reopened.
- **Most Firestore rules are still `allow read, write: if true`** — `bookings`,
  `trips`, `client_trips`, `quotes`, `invoices`, `estimates` and
  `admin_settings`. Anyone can read or modify them. Locking them down requires
  the portals to authenticate as real users first, so it depends on the item
  above.
- **The Google Maps API key** in `schedule.html` and `account.html` needs an
  HTTP-referrer restriction in Google Cloud Console, or usage can be billed to
  you by anyone who copies it.
