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

**5. admin.html now has a real sign-in** — Firebase Auth email/password.
Authorisation is the email allowlist `ADMIN_EMAILS`, which exists in three
places that must stay in step: `functions/index.js` (authoritative, for the
callables), `firestore.rules` (`isAdmin()`), and `admin.html` (UI only).
Currently `ramon@seacoastrvip.com`.

What it replaced: `var PWD = 'seacoast2025'` written in the page source, a
second comparison against driver passwords held in localStorage, a `debug-info`
box that printed the typed password back on screen, and a gate that unlocked on
`localStorage['rv-auth'] === '1'`. The Firestore listeners also ran at page
load, so the whole dashboard was fetched before the gate.

Verified locally: with `rv-auth` forced to `'1'` the dashboard stays hidden,
`_syncStarted` is false and **zero** Firestore requests are issued before
sign-in. Signing out now also clears the `rv-bks` and `rv-estimates` caches.

Drivers sign in with their own Firebase Auth account; the driver view appears
when a `drivers/{uid}` document exists. An account that is neither admin nor
driver is signed straight back out.

**6. `admin_settings` is locked** to `isAdmin()` — it is the only collection
admin.html alone uses, so it could be closed without breaking anything.

**7. The portals now have a Firebase Auth identity.** `clientLogin` and
`corporateLogin` mint a custom token after verifying the password, and the
portals sign in with it. The claims are `portal` ('client'/'corporate'),
`clientId`, `accountId`, `portalEmail`, `portalPhone` — prefixed to stay clear
of the names Firebase reserves on a custom token. This is what finally gives
Firestore an identity to authorise a booking against.

The iOS app rules were changed in the same deploy, from `request.auth != null`
to `isAppUser()` (= signed in **and** not a portal token). Without that, every
portal customer would have gained read access to every app user, driver and
ride the moment the portals started authenticating. App and admin tokens carry
no `portal` claim, so their access is unchanged — but this is worth a smoke
test from a device.

**8. Four more collections closed** — `client_trips`, `invoices`, `quotes` and
`estimates` are now `isAdmin()`. Verified denied to an anonymous caller, while
`clients` and `corporate_accounts` stay readable because the portals need them.

## Blocked on one IAM grant

**Token minting does not work yet.** `createCustomToken` needs
`iam.serviceAccounts.signBlob` on the functions' own service account.
`clientLogin` runs as `684535453116-compute@developer.gserviceaccount.com`,
which has `roles/editor` — and `roles/editor` does **not** include that
permission (checked, not assumed). Run this once:

```bash
gcloud iam service-accounts add-iam-policy-binding 684535453116-compute@developer.gserviceaccount.com --member="serviceAccount:684535453116-compute@developer.gserviceaccount.com" --role="roles/iam.serviceAccountTokenCreator" --project seacoast-rip
```

Until then `mintPortalToken` catches the failure and returns `null`, so sign-in
still works — grep the function logs for `mintPortalToken failed` to confirm.
Because no token is issued, the portal gates **must** still accept a plain
localStorage session, which means this hole is still open:

> Setting `localStorage['rvip-client-id']` to any client id opens that
> customer's dashboard, and a forged `corp_session` opens any company's portal.
> Demonstrated locally — it works today.

After the grant, the remaining work is: make both gates require a matching
claim (remove the legacy fallbacks marked `LEGACY PATH` in account.html and the
gate comments in corporate.html / corporate-portal.html), then restrict
`bookings`, `trips`, `clients` and `corporate_accounts` to owner-or-admin using
the claims. `bookings` create must stay open for the public booking form on
`schedule.html`.

## Needs you

**Create the admin Firebase Auth account.** I did not create it: that means
choosing a password, which is yours to set. Firebase Console → Authentication →
Users → Add user, with `ramon@seacoastrvip.com`. Email/Password is already
enabled on the project (verified). After that, "Forgot password?" on the admin
login works for future resets.

**Delete the leftover `adminPassword` field and change that password.** The old
"Change Password" card stored the admin password as **plain text** in
`admin_settings/main`, and that collection was world-readable, so a
12-character password was public to anyone with the API key from the page
source. The rules deploy closed the exposure, but the field is still in the
document and should be assumed compromised. My attempt to delete it was blocked
by a permission guard, so: Firebase Console → Firestore → `admin_settings` →
`main` → delete `adminPassword`. Do not reuse that password for the new Auth
account.

**Reopen `/admin` when you are ready** — remove its two lines from
`vercel.json`. It is still paused; you cannot sign in until the account above
exists, so create it first and test.

**3. The `admin: true` custom claim is still not set, and is not needed.**
`requireAdmin()` accepts either the claim or an allowlisted email, and the
email path is what admin.html uses. The claim remains available for service
accounts. Setting it would need Application Default Credentials, which this
machine lacks (`~/.config/gcloud` is empty).

## Still open

- **`bookings` and `trips` are still `allow read, write: if true`**, as are
  reads of `clients` and `corporate_accounts`. Anyone with the API key from the
  page source can read every booking and every customer's name, email and
  phone. Closing this is the single biggest remaining item and it depends on
  the IAM grant above.
- **The Google Maps API key** in `schedule.html` and `account.html` needs an
  HTTP-referrer restriction in Google Cloud Console, or anyone who copies it
  can bill usage to you.
- **`functions/package.json` pins an outdated `firebase-functions`.** The
  deploy warned about it. Upgrading has breaking changes, so it needs its own
  pass.

## Deploy note

Function deploys from this volume fail the trigger-discovery step with
"User code failed to load … Timeout after 10000" — the default 10s is not
enough here, though the module itself loads in 0.3s. Prefix the command:

```bash
FUNCTIONS_DISCOVERY_TIMEOUT=180 firebase deploy --only functions
```

`firestore:rules` is unaffected. Note that when the functions step fails, the
rules are compiled but **not** released, so deploy rules separately if you need
them out.

## Checks to run against the live site

- Sign in at `/corporate` with a real account — it should reach the portal.
- Sign in at `/account` with both a phone and an email account.
- A wrong password should say "Incorrect email/phone or password."
- Change a password inside each portal — it now asks for the current one.
