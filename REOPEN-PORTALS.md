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

**9. The IAM grant was made, so token minting works.** Confirmed with a
throwaway `diagnoseTokenMinting` callable that returned `{ok:true,signed:true}`
and was then deleted. `684535453116-compute@developer.gserviceaccount.com` now
holds `roles/iam.serviceAccountTokenCreator` on itself; `roles/editor` alone
does not include `iam.serviceAccounts.signBlob`.

**10. The impersonation holes are closed.** Session restore now requires a
Firebase Auth token whose claim matches the account being opened. Verified
against the live site: planting `rvip-client-id` leaves the login screen up and
the key is deleted, and a forged `corp_session` bounces back to
`/corporate.html`. Both of those opened the account before this change.

The login paths stay lenient on purpose — they have just verified the password
server-side, so a minting hiccup costs session persistence, not access.

**11. The booking data is closed.** `bookings`, `trips`, `corporate_accounts`
and `clients/{id}/trips` all deny anonymous reads now (verified from outside
with the public API key). Every booking the business has taken was readable by
anyone before this.

`bookings` read is **any signed-in caller**, not owner-only. The portals fan
out several queries per load — by `corporateAccountId`, by company, by contact
email, by three phone formats and one per corporate member — and Firestore
denies a query it cannot prove against the rules, which would take the whole
page's `Promise.all` down. Owner-only needs `clientId` /
`corporateAccountId` backfilled onto the older booking documents and those
loaders made fault-tolerant first. That is the next piece of work.

**12. Two unauthenticated writes to `clients` removed.**
`clientRequestEmailSetup` replaces two direct browser writes that let anyone
set the email address on a passwordless client record and then have a sign-in
link sent to it — an account-takeover path. `clientPortalSession` issues portal
claims to someone already signed in by email link, SMS or social, resolving the
client only from their *verified* token, so their trips keep loading under the
new subcollection rule.

## Needs you

**Create the admin Firebase Auth account.** I did not create it: that means
choosing a password, which is yours to set. Firebase Console → Authentication →
Users → Add user, with `ramon@seacoastrvip.com`. Email/Password is already
enabled on the project (verified). After that, "Forgot password?" on the admin
login works for future resets.

**Delete the leftover `adminPassword` field and change that password.** Still
present as of the last check — I tried twice and the permission guard blocked
the write both times. The old
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

## Done, continued

**13. The customer list is closed.** `clients` reads are own-record-or-admin.
Lookups by email or phone go through `clientLookup`, which answers only for the
identifier supplied and returns only `publicClientView` fields — never address,
balance or payment history. Verified: a list query and a single document both
deny anonymous reads.

**14. Sign-in is rate limited.** Eight failures against one identifier within
fifteen minutes locks it for fifteen minutes; counters live in `auth_throttle`,
which no client can read or write. Verified against the live endpoint — the
ninth attempt returns `resource-exhausted`. **Trade-off:** the lock is keyed on
the identifier, so someone can deliberately lock out a customer whose email
they know. Per-IP (or identifier+IP) is the follow-up.

**15. The booking form no longer publishes the corporate client list.**
`schedule.html` used to download every Approved/Active corporate account —
companies, contacts, whole member lists — to match one phone number.
`linkBookingToCorporate` does it server-side and returns only whether a link
was made.

**16. The browser API key is restricted.** Allowed referrers:

```
https://www.seacoastrvip.com/*      https://seacoastrvip.com/*
https://seacoast-rip.firebaseapp.com/*   https://seacoast-rip.web.app/*
http://localhost:8777/*             http://localhost:3000/*
```

**`seacoast-rip.firebaseapp.com` is not optional.** It is the Firebase
`authDomain`, and the sign-in handler for email-link and social logins runs
from there. Leaving it out breaks sign-in with
`API_KEY_HTTP_REFERRER_BLOCKED` from `identitytoolkit.googleapis.com` — which
is exactly what happened on the first attempt. Any new host that serves these
pages (a Vercel preview URL, a new domain) has to be added here too.

**What this restriction is and isn't:** a `Referer` header is trivially forged,
so it is not a security boundary. Identity Toolkit *does* enforce it (see
above) and so do the Maps APIs, which is the point — it stops someone copying
the key into their own site and billing Maps usage to this project. It gives no
data protection; the Firestore rules do that. Firestore itself appears not to
enforce referrer restrictions at all — an anonymous REST read with a forged or
absent referrer was still allowed in testing.

Only the Maps **JavaScript** API is used. Maps REST web services reject
referrer-restricted keys outright, so don't introduce a call to one.

**17. `bookings` is owner-only.** `isAdmin() || isDriver() || ownsBooking()`,
matching `clientId` or `corporateAccountId` against the portal token's claims.
A customer can no longer read anyone else's bookings.

The backfill was not needed in the end: of 81 bookings, 77 already carried an
owner field, and the four that did not match no client record — they were never
visible to a customer and remain visible to admin.
`backfillBookingOwners` stays deployed and unrun in case a future import
leaves documents unstamped:

```bash
curl -s -X POST "https://us-central1-seacoast-rip.cloudfunctions.net/backfillBookingOwners" -H "Content-Type: application/json" -d '{"data":{"confirm":"BACKFILL"}}'
```

Both portals previously fanned out queries by company, contact email and
several phone formats (and in the corporate portal, the same per member) to
catch unstamped bookings. Firestore rejects a query it cannot prove against the
rules, so those now query the owner field only. **Don't reintroduce one** — in
`account.html` a rejected listener takes the trip list with it.

`update` now matches `read` — `isAdmin() || isDriver() || ownsBooking()`. It
could be narrowed once `schedule.html` stopped updating a booking straight
after creating it (that work moved into `linkBookingToCorporate`), so the only
remaining anonymous write to `bookings` is the create itself.

**18. Every page is reopened.** `/schedule` (Book Now pointed at a paused
page), `/payment` and `/driver-portal` are all live; `/secure-access` stays in
the repo, unused.

Reopening `/schedule` exposed that the owner-only bookings rule had broken
`payment.html`, which found a booking with an anonymous
`where('code','==',...)` query — whoever is paying holds a code, not a
session. Two callables replace it: `bookingByCode` (verified against a real
code to return no email, phone, clientId or address) and
`markBookingAchInitiated`, which requires the booking's own code.

`driver-portal.html` keyed driver documents by phone number while all five
real documents are keyed by Auth uid, and the drivers rule only permits a
write where `uid == driverId` — so it could never find an existing driver and
its attempt to create one was refused. Fixed to resolve by uid, which also
makes `isDriver()` work for the bookings rule.

**19. App Check is registered and reporting.** The web app's config existed
with no `siteKey`; it now points at the SCORE-type reCAPTCHA Enterprise key
`6Lc3p6AsAAAAAMPlRgQjUPSMhptb7-_PAVB2goTa`, and the client SDK is activated on
all seven Firebase pages. Verified on the live domain that a token is issued,
with no console errors. **Every service is still UNENFORCED.**

## Finishing App Check

Tokens are flowing, so the console's App Check metrics will fill up. Watch them
for a few days:

```
https://console.firebase.google.com/project/seacoast-rip/appcheck/apps
```

When verified requests dominate and unverified traffic is near zero, enforce
one service at a time — `firestore.googleapis.com` first, then the callables,
leaving `identitytoolkit.googleapis.com` until last.

**Do not enforce before the metrics look right.** Enforcing while clients are
still sending unverified requests takes that traffic offline immediately, and
with identitytoolkit that means nobody can sign in.

- The reCAPTCHA key allows `seacoastrvip.com` (covering `www.`) but not
  `localhost`, so App Check logs `appCheck/recaptcha-error` in local
  development. Expected, and harmless while unenforced.
- `driver-portal.html` is on Firebase 10.7.1, the others on 9.23.0. The App
  Check SDK version must match the app SDK on the same page.

## Still open

- **One real sign-in of each kind still wants testing by hand**: a personal
  account by phone and by email, a corporate account, and the email-link flow.
  The attack paths and error paths are verified, but not a successful login —
  that needs a real password.
- **A real booking and payment has not been put through.** `/schedule` creates
  the booking and `/payment` resolves it by code — both verified as far as
  they can be from outside — but no one has run a live booking through to a
  Stripe charge.
- **A driver has not signed in since the uid fix.** The SMS flow needs one
  real test.
- **`adminPassword` is still on `admin_settings/main`.** Delete it in the
  console; the permission guard in this session refused the write every time.
  Treat that password as compromised.
- **App Check enforcement** — see above. Registered and reporting, not
  enforcing.
- **`bookings` update is owner-or-driver-or-admin**, which lets any signed-in
  driver modify any booking. Narrowing that needs the ride-assignment model
  revisited.
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
