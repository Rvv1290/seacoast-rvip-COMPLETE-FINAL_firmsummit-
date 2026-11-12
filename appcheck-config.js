// ─────────────────────────────────────────────────────────────────────────
//  Firebase App Check — WEBSITE (staged, OFF by default)
// ─────────────────────────────────────────────────────────────────────────
// App Check lets Firebase reject reads/writes that don't come from your real
// site or apps — the defense against scripted spam on the public booking /
// signup / corporate forms. The iOS/driver apps already send App Check tokens;
// this file adds the same for the website.
//
// It does NOTHING until you set RVIP_APPCHECK_KEY below. While it is empty,
// App Check stays off and the site behaves exactly as before.
//
// ── IMPORTANT: this project already has a web key ──────────────────────────
// The Firebase project (seacoast-rip) was previously set up with a reCAPTCHA
// **Enterprise** key for the web app:
//     6Lc3p6AsAAAAAMPlRgQjUPSMhptb7-_PAVB2goTa   ("Seacoast RVIP LLC")
//     allowed domain: seacoastrvip.com (covers www.; NOT localhost / previews)
// First confirm it is still registered: Firebase Console → App Check → Apps →
// the web app. If it is, just paste it below and leave the provider as
// 'enterprise'. If you register a fresh reCAPTCHA v3 key instead, set the
// provider to 'v3'. (A reCAPTCHA v3 key and an Enterprise key are NOT
// interchangeable — the provider must match the key's type.)
//
// ── Staged rollout (do NOT skip) ───────────────────────────────────────────
//   1. Confirm/choose the site key above and paste it below.
//   2. Deploy. Leave Firestore/Functions UNENFORCED in the console and watch
//      App Check → Metrics for a few days: "verified" should climb, real users
//      should not show as "unverified".
//   3. Only when metrics are clean, switch Firestore (then Functions) to
//      "Enforced" in the console. That is when spam without a valid token is
//      blocked. Enforcing is a console toggle — no code change.
//
// The site key is public and safe to commit (it ships in the page like the
// Firebase apiKey). The matching secret stays in Google only.

window.RVIP_APPCHECK_KEY      = '';            // ← paste the site key here to turn on
window.RVIP_APPCHECK_PROVIDER = 'enterprise';  // 'enterprise' (existing key) or 'v3'

// Called by each page right after firebase.initializeApp(). Safe to call with
// no key (returns quietly) and never throws into the page.
window.RVIP_ACTIVATE_APPCHECK = function () {
  try {
    var key = window.RVIP_APPCHECK_KEY;
    if (!key || !window.firebase || !firebase.appCheck) return;

    var ac = firebase.appCheck;
    var provider;
    if (window.RVIP_APPCHECK_PROVIDER === 'v3' && ac.ReCaptchaV3Provider) {
      provider = new ac.ReCaptchaV3Provider(key);
    } else if (ac.ReCaptchaEnterpriseProvider) {
      provider = new ac.ReCaptchaEnterpriseProvider(key);
    } else {
      provider = key; // last-resort: compat treats a bare string as v3
    }
    firebase.appCheck().activate(provider, /* autoRefresh */ true);
    console.log('[AppCheck] website App Check activated (' +
                (window.RVIP_APPCHECK_PROVIDER || 'enterprise') + ')');
  } catch (e) {
    console.warn('[AppCheck] not activated:', e && e.message);
  }
};
