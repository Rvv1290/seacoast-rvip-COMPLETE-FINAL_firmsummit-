// ─────────────────────────────────────────────────────────────────────────
//  Firebase App Check — WEBSITE (staged, OFF by default)
// ─────────────────────────────────────────────────────────────────────────
// App Check lets Firebase reject reads/writes that don't come from your real
// site or apps — the defense against scripted spam on the public booking /
// signup / corporate forms. The iOS/driver apps already send App Check tokens;
// this file adds the same for the website.
//
// It does NOTHING until you put a key below. While RVIP_APPCHECK_KEY is empty,
// App Check stays off and the site behaves exactly as before.
//
// TO TURN IT ON (staged rollout — do NOT skip steps):
//   1. Firebase Console → App Check → Apps → register this WEB app with the
//      "reCAPTCHA v3" provider. Copy the reCAPTCHA v3 SITE key it gives you.
//   2. Paste that site key between the quotes on the RVIP_APPCHECK_KEY line.
//   3. Deploy the site. In the console, leave Firestore/Functions UNENFORCED
//      and watch App Check → Metrics for a few days: "verified" requests should
//      climb and real users should not be getting "unverified".
//   4. Only once metrics look clean, switch Firestore (and Functions) to
//      "Enforced" in the console. That is the moment spam without a valid token
//      starts being blocked. Enforcing is a console toggle — no code change.
//
// NOTE: the reCAPTCHA v3 SITE key is public and safe to commit (it ships in the
// page like the Firebase apiKey). The matching SECRET key stays in Google only.

window.RVIP_APPCHECK_KEY = ''; // ← paste your reCAPTCHA v3 SITE key here

// Called by each page right after firebase.initializeApp(). Safe to call with
// no key (returns quietly) and never throws into the page.
window.RVIP_ACTIVATE_APPCHECK = function () {
  try {
    var key = window.RVIP_APPCHECK_KEY;
    if (key && window.firebase && firebase.appCheck) {
      firebase.appCheck().activate(key, /* autoRefresh */ true);
      console.log('[AppCheck] website App Check activated');
    }
  } catch (e) {
    console.warn('[AppCheck] not activated:', e && e.message);
  }
};
