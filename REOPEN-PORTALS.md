# Portal status

Last run: November 2, 2026.

## Done

**1. Functions and rules deployed** — `firebase deploy --only functions,firestore:rules`
against project `seacoast-rip`. Rules compiled and released. Fifteen functions
live: six created (`migrateCorporatePasswords`, `corporateSetTempPassword`,
`clientLogin`, `clientSetPassword`, `clientSetTempPassword`,
`migrateClientPasswords`), nine updated.

**2. Both password migrations run once.**

| Migration | Result |
| --- | --- |
| `migrateCorporatePasswords` | total 2, already hashed 2, **remaining 0** |
| `migrateClientPasswords` | total 21, hashed 10, no password 11, **remaining 0** |

Verified afterwards straight from the public internet, using the web API key
that ships in the page source:

- `clients` — 21 documents, **0** with a `password` field
- `corporate_accounts` — 2 documents, **0** with a `password` field
- `client_auth` — "Missing or insufficient permissions"
- `corporate_auth` — "Missing or insufficient permissions"

Endpoint smoke test: `clientLogin` → 404 "No account found…",
`corporateLogin` → 401 "Incorrect email/phone or password.",
`clientSetTempPassword` without an admin claim → 403 "Administrator sign-in
required."

**4. `/account`, `/corporate` and `/corporate-portal` reopened** — the six
redirects removed from `vercel.json`.

Still paused: `/driver-portal`, `/admin`, `/schedule`, `/payment`.

## Not done, on purpose

**3. The `admin: true` custom claim is not set.** It would have no effect today:
`admin.html` performs no sign-in, so no Firebase Auth token ever reaches the
admin-only callables, claim or not. Setting it also needs Application Default
Credentials, which this machine does not have (`~/.config/gcloud` is empty).
Do it as part of building the admin sign-in, not before. Command for then:

```bash
cd "/Volumes/RAMON VV/seacoast-rvip-LIVE/functions" && node -e "const a=require('firebase-admin');a.initializeApp();a.auth().getUserByEmail(process.argv[1]).then(u=>a.auth().setCustomUserClaims(u.uid,{admin:true})).then(()=>console.log('admin claim set')).catch(e=>{console.error(e.message);process.exit(1)})" YOUR_ADMIN_EMAIL
```

Consequence until then: **Approve Client** and **Portal Access** in admin.html
return "Administrator sign-in required." Everything else in admin works.

## Still open

- **admin.html has no authentication.** Anyone who reaches the URL gets full
  control of bookings, clients, drivers and corporate accounts. The
  `/secure-access` redirect is obscurity, not protection — the Firebase config
  is in the page source, so the data is reachable without the page. This is the
  largest remaining hole and it blocks the rules lockdown below. Keep `/admin`
  paused until it has a real sign-in (Firebase Auth email/password plus the
  claim above).
- **Most Firestore rules are still `allow read, write: if true`** — `bookings`,
  `trips`, `client_trips`, `quotes`, `invoices`, `estimates` and
  `admin_settings`. Locking them down requires the portals to authenticate as
  real Firebase Auth users first; today they use localStorage sessions, so
  there is no identity to write a rule against.
- **The Google Maps API key** in `schedule.html` and `account.html` needs an
  HTTP-referrer restriction in Google Cloud Console, or anyone who copies it
  can bill usage to you.
- **`functions/package.json` pins an outdated `firebase-functions`.** The
  deploy warned about it. Upgrading has breaking changes, so it needs its own
  pass.

## Checks to run against the live site

- Sign in at `/corporate` with a real account — it should reach the portal.
- Sign in at `/account` with both a phone and an email account.
- A wrong password should say "Incorrect email/phone or password."
- Change a password inside each portal — it now asks for the current one.
