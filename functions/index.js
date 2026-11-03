const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
admin.initializeApp();

const stripeSecret = defineSecret("STRIPE_SECRET");

// SMTP connection string for outgoing mail, e.g.
//   smtps://info%40seacoastrvip.com:APP_PASSWORD@smtp.gmail.com:465
// Set it with:  firebase functions:secrets:set SMTP_URL
const smtpUrl = defineSecret("SMTP_URL");

// ── Sign-in throttling ───────────────────────────────────────────────────────
// clientLogin and corporateLogin verify passwords server-side, so without this
// an attacker could guess at whatever rate the network allows. Counters live in
// auth_throttle, which no client can read or write.
const THROTTLE_MAX = 8;                       // failures before a lock
const THROTTLE_IP_MAX = 30;                   // ...and per caller IP, which is
                                              // shared by households and
                                              // offices, so it runs looser
const THROTTLE_WINDOW_MS = 15 * 60 * 1000;    // ...within this window
const THROTTLE_LOCK_MS = 15 * 60 * 1000;      // ...locks for this long

function throttleRef(db, identifier) {
  const key = require("crypto").createHash("sha256")
    .update(String(identifier || "").trim().toLowerCase())
    .digest("hex").slice(0, 40);
  return db.collection("auth_throttle").doc(key);
}

// Caller IP, for the second throttle dimension.
function callerIp(request) {
  const r = request.rawRequest || {};
  const fwd = (r.headers && (r.headers["x-forwarded-for"] || r.headers["X-Forwarded-For"])) || "";
  const first = String(fwd).split(",")[0].trim();
  return first || r.ip || "";
}

/**
 * Guards a sign-in attempt on two keys at once: the identifier and the caller's
 * IP. The identifier key alone means anyone who knows a customer's email can
 * lock them out for the window, so the IP key carries a larger budget and is
 * what actually stops distributed guessing against one account.
 */
async function throttleRefs(db, scope, identifier, request) {
  const refs = [throttleRef(db, scope + ":" + identifier)];
  const ip = callerIp(request);
  if (ip) refs.push(throttleRef(db, "ip:" + scope + ":" + ip));
  return refs;
}

// Throws if the identifier is currently locked out.
async function throttleGuard(ref) {
  const doc = await ref.get();
  if (!doc.exists) return;
  const d = doc.data() || {};
  const now = Date.now();
  if (d.lockedUntil && d.lockedUntil > now) {
    const mins = Math.ceil((d.lockedUntil - now) / 60000);
    throw new HttpsError(
      "resource-exhausted",
      `Too many sign-in attempts. Try again in ${mins} minute${mins === 1 ? "" : "s"}.`
    );
  }
}

async function throttleFailure(ref, max) {
  const now = Date.now();
  const limit = max || THROTTLE_MAX;
  try {
    await admin.firestore().runTransaction(async (tx) => {
      const doc = await tx.get(ref);
      const d = doc.exists ? (doc.data() || {}) : {};
      const inWindow = d.windowStart && (now - d.windowStart) < THROTTLE_WINDOW_MS;
      const windowStart = inWindow ? d.windowStart : now;
      const count = (inWindow ? (d.count || 0) : 0) + 1;
      const upd = { windowStart, count, updatedAt: now };
      if (count >= limit) {
        upd.lockedUntil = now + THROTTLE_LOCK_MS;
        upd.count = 0;
        upd.windowStart = now;
      }
      tx.set(ref, upd, { merge: true });
    });
  } catch (e) {
    // Never let bookkeeping turn a wrong password into a server error.
    console.error("throttleFailure:", e.message);
  }
}

async function throttleClear(ref) {
  try { await ref.delete(); } catch (e) { /* nothing recorded */ }
}

/**
 * Mints a Firebase Auth session for a portal customer after their password has
 * already been verified.
 *
 * The portals used to run on a localStorage flag alone. Firestore therefore had
 * no identity to authorise against, which is why every booking collection had
 * to stay world-readable. These claims are what firestore.rules matches a
 * document's owner against.
 *
 * Claim names are prefixed (portalEmail, not email) to stay clear of the names
 * Firebase reserves on a custom token, and `portal` marks the token as a
 * customer session so the iOS app's own collections can exclude it.
 */
async function mintPortalToken(kind, docId, data) {
  const d = data || {};
  const claims = { portal: kind };
  if (kind === "client") {
    claims.clientId = String(docId);
    if (d.corporateAccountId) claims.accountId = String(d.corporateAccountId);
  } else {
    claims.accountId = String(docId);
  }
  const email = String(d.email || "").trim().toLowerCase();
  if (email) claims.portalEmail = email;
  const phone = String(d.phone || "").replace(/\D/g, "").slice(-10);
  if (phone.length === 10) claims.portalPhone = phone;
  try {
    return await admin.auth().createCustomToken(`${kind}_${docId}`, claims);
  } catch (e) {
    // Minting needs iam.serviceAccounts.signBlob on the function's own service
    // account, which is not granted by default on 2nd-gen functions. Never let
    // that break sign-in: the caller falls back to the pre-token behaviour and
    // this line is the thing to grep for in the logs.
    console.error("mintPortalToken failed — portal session not issued:", e.message);
    return null;
  }
}

// Resolves the Firestore ref+doc for an account. Supports both
// corporate_accounts (default) and clients collections so the same
// functions work for the corporate portal and the personal client portal.
async function resolveAccountDoc(accountId, collection) {
  const db = admin.firestore();
  const col = (collection === "clients") ? "clients" : "corporate_accounts";
  const ref = db.collection(col).doc(accountId);
  const doc = await ref.get();
  if (!doc.exists) throw new HttpsError("not-found", `${col} document not found`);
  return { ref, doc };
}

/**
 * Ensures a Stripe Customer exists for a corporate account or personal client.
 * Pass collection:'clients' for personal-account callers.
 */
exports.getStripeCustomer = onCall({ secrets: [stripeSecret] }, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, email, company, collection } = request.data;

  if (!accountId) throw new HttpsError("invalid-argument", "Missing Account ID");

  const { ref, doc } = await resolveAccountDoc(accountId, collection);
  const data = doc.data();

  // If we already have a customer ID, make sure it actually exists in THIS Stripe
  // account. After switching Stripe accounts the old ID is invalid, which breaks
  // PaymentIntent creation — so verify it, and fall through to create a fresh one
  // (clearing the now-dead saved-card data) if it's missing.
  if (data.stripeCustomerId) {
    try {
      const existing = await stripe.customers.retrieve(data.stripeCustomerId);
      if (existing && !existing.deleted) return { customerId: data.stripeCustomerId };
    } catch (e) {
      // not found in this account — create a new one below
    }
  }

  const customer = await stripe.customers.create({
    email: email || data.contactEmail || data.email || "",
    name: company || data.company || data.name || "",
    metadata: { accountId },
  });

  await ref.update({
    stripeCustomerId: customer.id,
    stripePaymentMethodId: admin.firestore.FieldValue.delete(),
    cardBrand: admin.firestore.FieldValue.delete(),
    cardLast4: admin.firestore.FieldValue.delete(),
  });
  return { customerId: customer.id };
});

/**
 * Creates a PaymentIntent and returns its client secret so the front-end
 * can mount the Stripe Payment Element.
 */
exports.createPaymentIntent = onCall({ secrets: [stripeSecret] }, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { amount, bookingCode, customerName, customerId } = request.data;

  if (!amount || parseFloat(amount) <= 0) {
    throw new HttpsError("invalid-argument", "Invalid amount");
  }

  const piParams = {
    amount: Math.round(parseFloat(amount) * 100),
    currency: "usd",
    automatic_payment_methods: { enabled: true },
    metadata: {
      bookingCode: bookingCode || "",
      customerName: customerName || "",
    },
  };

  if (customerId) {
    piParams.customer = customerId;
    piParams.setup_future_usage = "off_session";
  }

  let paymentIntent;
  try {
    paymentIntent = await stripe.paymentIntents.create(piParams);
  } catch (e) {
    // If the customer is invalid (e.g. a stale ID from a previous Stripe account),
    // retry without it so the payment form still loads.
    if (piParams.customer) {
      delete piParams.customer;
      delete piParams.setup_future_usage;
      paymentIntent = await stripe.paymentIntents.create(piParams);
    } else {
      throw e;
    }
  }
  return { clientSecret: paymentIntent.client_secret };
});

/**
 * Generates a SetupIntent client secret for saving a card without an
 * immediate charge.
 */
exports.createSetupIntent = onCall({ secrets: [stripeSecret] }, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { customerId } = request.data;
  if (!customerId) throw new HttpsError("invalid-argument", "Missing Customer ID");

  const setupIntent = await stripe.setupIntents.create({
    customer: customerId,
    payment_method_types: ["card"],
  });

  return { clientSecret: setupIntent.client_secret };
});

/**
 * Charges the saved payment method for a corporate account or personal client.
 * Pass collection:'clients' for personal-account callers.
 */
exports.chargeSavedCard = onCall({ secrets: [stripeSecret] }, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, amount, collection } = request.data;

  if (!accountId || !amount || amount <= 0) {
    throw new HttpsError("invalid-argument", "Invalid account or amount");
  }

  const { ref, doc } = await resolveAccountDoc(accountId, collection);
  const data = doc.data();
  const { stripeCustomerId: customerId, stripePaymentMethodId: paymentMethodId } = data;

  if (!customerId || !paymentMethodId) {
    throw new HttpsError("failed-precondition", "No saved payment method found");
  }

  const paymentIntent = await stripe.paymentIntents.create({
    amount: Math.round(amount * 100),
    currency: "usd",
    customer: customerId,
    payment_method: paymentMethodId,
    off_session: true,
    confirm: true,
  });

  if (paymentIntent.status === "succeeded") {
    await ref.update({
      balance: 0,
      lastPaymentDate: admin.firestore.FieldValue.serverTimestamp(),
      lastPaymentAmount: amount,
      lastPaymentId: paymentIntent.id,
    });
    return { success: true, paymentIntentId: paymentIntent.id };
  }

  return { success: false, status: paymentIntent.status };
});

/**
 * Persists a payment method ID (and card brand/last4) to Firestore.
 * Pass collection:'clients' for personal-account callers.
 */
exports.savePaymentMethod = onCall({ secrets: [stripeSecret] }, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, paymentMethodId, collection } = request.data;
  if (!accountId || !paymentMethodId) throw new HttpsError("invalid-argument", "Missing data");

  const { ref } = await resolveAccountDoc(accountId, collection);
  const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);

  await ref.update({
    stripePaymentMethodId: paymentMethodId,
    cardBrand: paymentMethod.card.brand,
    cardLast4: paymentMethod.card.last4,
  });

  return { success: true };
});

/**
 * Resets a corporate account password.
 * Runs with admin privileges so Firestore rules don't block the update.
 */
// Finds a corporate account by contact email/phone, or by a member's.
// Used by corporateLogin and the password reset.
async function _findCorpAccount(db, identifier) {
  const idRaw = String(identifier || "").trim();
  const idLower = idRaw.toLowerCase();
  const isEmail = idRaw.includes("@");
  const digits = idRaw.replace(/\D/g, "");
  const snap = await db.collection("corporate_accounts")
    .where("status", "in", ["Approved", "Active"]).get();
  let match = null;
  snap.forEach((d) => {
    if (match) return;
    const a = d.data();
    if (isEmail) {
      if ((a.contactEmail || "").toLowerCase().trim() === idLower) { match = { id: d.id, data: a }; return; }
      for (const m of (a.members || [])) {
        if ((m.email || "").toLowerCase().trim() === idLower) { match = { id: d.id, data: a }; return; }
      }
    } else if (digits.length >= 10) {
      const p = (a.contactPhone || "").replace(/\D/g, "");
      if (p && (p === digits || p.slice(-10) === digits.slice(-10))) { match = { id: d.id, data: a }; return; }
      for (const m of (a.members || [])) {
        const mp = (m.phone || "").replace(/\D/g, "");
        if (mp && (mp === digits || mp.slice(-10) === digits.slice(-10))) { match = { id: d.id, data: a }; return; }
      }
    }
  });
  return match;
}

/**
 * "Forgot password" for a corporate account.
 *
 * Delivery goes through Firebase Auth's own password-reset email, not our
 * SMTP. Google rejects the app password for info@seacoastrvip.com, so every
 * SMTP send fails — while Firebase's email, which the admin reset already
 * relies on, arrives reliably.
 *
 * This only makes sure a Firebase Auth user exists for the address; the page
 * then calls sendPasswordResetEmail. When the customer signs in afterwards,
 * corporate.html syncs that new password into corporate_auth, which is what
 * corporateLogin actually compares.
 *
 * Always reports success so the endpoint cannot be used to discover which
 * addresses have accounts.
 */
exports.corporateRequestPasswordReset = onCall(async (request) => {
  const email = String((request.data || {}).email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    throw new HttpsError("invalid-argument", "Enter a valid email address.");
  }

  const db = admin.firestore();
  // Throttled like sign-in: it provisions an auth user and triggers an email.
  const tRefs = await throttleRefs(db, "corpreset", email, request);
  for (const r of tRefs) await throttleGuard(r);

  const match = await _findCorpAccount(db, email);
  if (!match) {
    await Promise.all(tRefs.map((r, i) => throttleFailure(r, i === 0 ? THROTTLE_MAX : THROTTLE_IP_MAX)));
    return { success: true };
  }

  // The reset link has to have somewhere to land.
  try {
    await admin.auth().getUserByEmail(email);
  } catch (e) {
    if (e.code === "auth/user-not-found") {
      // No password set here: the customer chooses one through the reset link,
      // and signing in with it syncs the portal password.
      await admin.auth().createUser({
        email,
        emailVerified: false,
        displayName: match.data.company || undefined,
      });
    } else {
      console.error("corporateRequestPasswordReset getUserByEmail:", e.message);
      throw new HttpsError("internal", "Could not start the reset. Call (978) 255-3140.");
    }
  }

  return { success: true };
});

/**
 * Corporate portal login. Verifies the password server-side (bcrypt hash, with a
 * one-time plaintext fallback that upgrades to a hash). Returns the sanitized
 * account (no password) and whether a reset is required.
 */
exports.corporateLogin = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  const { identifier, password } = request.data || {};
  if (!identifier || !password) throw new HttpsError("invalid-argument", "Missing email/phone or password.");
  const db = admin.firestore();

  const tRefs = await throttleRefs(db, "corp", identifier, request);
  for (const r of tRefs) await throttleGuard(r);

  const match = await _findCorpAccount(db, identifier);
  if (!match) {
    await Promise.all(tRefs.map((r, i) => throttleFailure(r, i === 0 ? THROTTLE_MAX : THROTTLE_IP_MAX)));
    throw new HttpsError("unauthenticated", "Incorrect email/phone or password.");
  }

  const authRef = db.collection("corporate_auth").doc(match.id);
  const authDoc = await authRef.get();
  const storedHash = (authDoc.exists && authDoc.data().hash) ? authDoc.data().hash : null;
  let ok = false;

  // 1) Try the stored hash.
  if (storedHash) {
    ok = await bcrypt.compare(String(password), storedHash);
  }
  // 2) If there's no hash yet, OR the hash didn't match, fall back to the plaintext
  //    password on the account. This covers the first login before migration AND a
  //    password reset that wrote a new plaintext value after a hash already existed
  //    (admin Portal Access / a password reset). On a match, (re)write the hash so
  //    it stays in sync with the current password.
  if (!ok && match.data.password && String(match.data.password) === String(password)) {
    ok = true;
    const hash = await bcrypt.hash(String(password), 10);
    await authRef.set({ hash, migratedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await db.collection("corporate_accounts").doc(match.id)
      .update({ password: admin.firestore.FieldValue.delete(), hasPassword: true });
  }
  // 3) Nothing to check against at all. Hand back the account id so the sign-in
  //    page can run the "set your password" flow without reading Firestore itself.
  if (!ok && !storedHash && !match.data.password) {
    throw new HttpsError("failed-precondition", "No password is set for this account.", { accountId: match.id });
  }

  if (!ok) {
    await Promise.all(tRefs.map((r, i) => throttleFailure(r, i === 0 ? THROTTLE_MAX : THROTTLE_IP_MAX)));
    throw new HttpsError("unauthenticated", "Incorrect email/phone or password.");
  }
  await Promise.all(tRefs.map(throttleClear));

  const acc = Object.assign({ id: match.id }, match.data);
  delete acc.password;
  const authToken = await mintPortalToken("corporate", match.id, match.data);
  return {
    success: true,
    account: acc,
    authToken,
    passwordResetRequired: !!match.data.passwordResetRequired,
  };
});

/**
 * Sets a NEW corporate password (hashed). Requires the current password unless
 * none is set yet. Clears the legacy plaintext field and the reset flag.
 */
/**
 * Resolves the corporate account belonging to a verified Firebase Auth
 * session, so a customer who has just reset their password through the
 * Firebase link can have that password adopted as their portal password.
 *
 * Requires a verified email, for the reason in sessionOwnsCorpAccount:
 * signing up with an address does not prove you own it, completing a reset
 * does.
 */
exports.corporateAccountForSession = onCall(async (request) => {
  const t = request.auth && request.auth.token;
  if (!t) throw new HttpsError("unauthenticated", "Sign in first.");
  const email = String(t.email || "").trim().toLowerCase();
  if (!email || t.email_verified !== true) {
    throw new HttpsError("permission-denied", "Verify your email address first.");
  }
  const db = admin.firestore();
  const match = await _findCorpAccount(db, email);
  if (!match) return { found: false, accountId: null };
  return { found: true, accountId: match.id };
});

/**
 * Is this caller entitled to act on THIS corporate account?
 *
 * Previously any signed-in caller counted as a "verified session", so a
 * personal client — or anyone who had signed in at all — could set another
 * company's password by passing its accountId. The session now has to belong
 * to the account: an admin, a portal token minted for it, or a Firebase Auth
 * user whose VERIFIED email is the contact or a member.
 *
 * email_verified matters: plain email/password signup does not verify an
 * address, so without it someone could register another company's contact
 * email and take the account over. Completing a password reset does verify it,
 * which is the path this is for.
 */
function sessionOwnsCorpAccount(request, accountId, data) {
  const t = request.auth && request.auth.token;
  if (!t) return false;
  if (t.admin === true) return true;
  const email = String(t.email || "").trim().toLowerCase();
  if (ADMIN_EMAILS.includes(email)) return true;
  if (t.accountId && String(t.accountId) === String(accountId)) return true;
  if (email && t.email_verified === true) {
    if (String((data || {}).contactEmail || "").trim().toLowerCase() === email) return true;
    for (const m of ((data || {}).members || [])) {
      if (String((m || {}).email || "").trim().toLowerCase() === email) return true;
    }
  }
  return false;
}

exports.corporateSetCorporatePassword = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  const { accountId, currentPassword, newPassword } = request.data || {};
  if (!accountId || !newPassword) throw new HttpsError("invalid-argument", "Missing data.");
  if (String(newPassword).length < 6) throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");
  const db = admin.firestore();
  const ref = db.collection("corporate_accounts").doc(accountId);
  const doc = await ref.get();
  if (!doc.exists) throw new HttpsError("not-found", "Account not found.");
  const data = doc.data();

  const authRef = db.collection("corporate_auth").doc(accountId);
  const authDoc = await authRef.get();
  const hasHash = authDoc.exists && !!authDoc.data().hash;
  const hasPlain = !!data.password;

  // Authorised by the current password, or by a verified Firebase Auth session
  // (the SMS setup flow signs the user in before reaching here).
  const verifiedSession = sessionOwnsCorpAccount(request, accountId, data);
  if ((hasHash || hasPlain) && !verifiedSession) {
    let ok = false;
    if (hasHash) ok = await bcrypt.compare(String(currentPassword || ""), authDoc.data().hash);
    else ok = String(currentPassword || "") === String(data.password);
    if (!ok) throw new HttpsError("permission-denied", "Current password is incorrect.");
  }
  if (!hasHash && !hasPlain && !verifiedSession) {
    // Claiming a passwordless account requires a verified email or phone first.
    throw new HttpsError("permission-denied", "Verify your email or phone before setting a password.");
  }

  const hash = await bcrypt.hash(String(newPassword), 10);
  await authRef.set({ hash, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await ref.update({
    password: admin.firestore.FieldValue.delete(),
    hasPassword: true,
    passwordResetRequired: false,
    updatedAt: new Date().toISOString(),
  });
  return { success: true };
});

/**
 * One-time migration. Hashes every remaining plaintext `password` on a
 * corporate_accounts document into the locked corporate_auth collection and
 * deletes the plaintext field.
 *
 * corporate_accounts is readable by the portal pages, so any password stored on
 * those documents is readable by anyone holding the public Firebase config.
 * Run this once, then confirm `remaining` is 0.
 *
 * Call it signed in as an admin:
 *   firebase functions:shell  →  migrateCorporatePasswords({confirm:'MIGRATE'})
 */
exports.migrateCorporatePasswords = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  if (!request.data || request.data.confirm !== "MIGRATE") {
    throw new HttpsError("invalid-argument", "Pass { confirm: 'MIGRATE' } to run this migration.");
  }
  const db = admin.firestore();
  const snap = await db.collection("corporate_accounts").get();

  let hashed = 0, alreadyHashed = 0, noPassword = 0;
  for (const doc of snap.docs) {
    const plain = doc.data().password;
    if (!plain) { noPassword++; continue; }
    const authRef = db.collection("corporate_auth").doc(doc.id);
    const authDoc = await authRef.get();
    if (!(authDoc.exists && authDoc.data().hash)) {
      const hash = await bcrypt.hash(String(plain), 10);
      await authRef.set({ hash, migratedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      hashed++;
    } else {
      alreadyHashed++;
    }
    await doc.ref.update({ password: admin.firestore.FieldValue.delete(), hasPassword: true });
  }

  // Re-read to prove no plaintext password survives.
  const after = await db.collection("corporate_accounts").get();
  const remaining = after.docs.filter((d) => !!d.data().password).length;

  return { success: true, total: snap.size, hashed, alreadyHashed, noPassword, remaining };
});

/**
 * Admin "Portal Access" temporary password. Writes a bcrypt hash only; the
 * caller receives the generated password once so it can be read out to the
 * client, and nothing is stored in plaintext.
 */
exports.corporateSetTempPassword = onCall(async (request) => {
  requireAdmin(request);
  const bcrypt = require("bcryptjs");
  const { accountId, password } = request.data || {};
  if (!accountId) throw new HttpsError("invalid-argument", "Missing accountId.");
  if (password && String(password).length < 6) {
    throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");
  }

  const db = admin.firestore();
  const ref = db.collection("corporate_accounts").doc(accountId);
  if (!(await ref.get()).exists) throw new HttpsError("not-found", "Account not found.");

  const tempPwd = password ? String(password) : "RVIP" + Math.random().toString(36).slice(-6).toUpperCase();
  const hash = await bcrypt.hash(tempPwd, 10);
  await db.collection("corporate_auth").doc(accountId)
    .set({ hash, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await ref.update({
    password: admin.firestore.FieldValue.delete(),
    hasPassword: true,
    passwordResetRequired: true,
  });
  return { success: true, tempPassword: tempPwd };
});

// ─────────────────────────────────────────────────────────────────────────────
//  SECURE CLIENT AUTH
//  Mirrors the corporate flow. Personal-client passwords live only as bcrypt
//  hashes in the locked `client_auth/{clientId}` collection. The `clients`
//  collection is readable by the portal pages, so it must never hold one.
// ─────────────────────────────────────────────────────────────────────────────

// Accounts allowed to act as administrators, by the email on their verified
// Firebase Auth token. This is the authoritative list — the copy in admin.html
// only decides what the UI shows, and editing that copy grants nothing.
// An `admin: true` custom claim also works, for service accounts or if you
// would rather manage this through claims later.
const ADMIN_EMAILS = ["ramon@seacoastrvip.com"];

// Caller must be signed in with Firebase Auth as an administrator.
function requireAdmin(request) {
  const token = request.auth && request.auth.token;
  if (!token) {
    throw new HttpsError("unauthenticated", "Administrator sign-in required.");
  }
  if (token.admin === true) return;
  const email = String(token.email || "").toLowerCase();
  if (email && ADMIN_EMAILS.includes(email)) return;
  throw new HttpsError("permission-denied", "Administrator sign-in required.");
}

// Every phone shape the website has ever stored.
function _phoneFormats(digits) {
  const d = String(digits || "").replace(/\D/g, "").slice(-10);
  if (d.length < 10) return [];
  return [
    "+1" + d, d,
    `(${d.slice(0, 3)}) ${d.slice(3, 6)}-${d.slice(6)}`,
    `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`,
  ];
}

async function _findClient(db, identifier) {
  const idRaw = String(identifier || "").trim();
  if (!idRaw) return null;
  if (idRaw.includes("@")) {
    for (const e of [idRaw, idRaw.toLowerCase()]) {
      const snap = await db.collection("clients").where("email", "==", e).limit(1).get();
      if (!snap.empty) return { id: snap.docs[0].id, data: snap.docs[0].data() };
    }
    return null;
  }
  for (const p of _phoneFormats(idRaw)) {
    const snap = await db.collection("clients").where("phone", "==", p).limit(1).get();
    if (!snap.empty) return { id: snap.docs[0].id, data: snap.docs[0].data() };
  }
  return null;
}

/**
 * Personal client sign-in. Verifies a bcrypt hash in client_auth, with a
 * one-time plaintext fallback that upgrades the stored password to a hash so
 * nobody is locked out mid-migration.
 */
exports.clientLogin = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  const { identifier, password } = request.data || {};
  if (!identifier || !password) throw new HttpsError("invalid-argument", "Missing email/phone or password.");
  const db = admin.firestore();

  const tRefs = await throttleRefs(db, "client", identifier, request);
  for (const r of tRefs) await throttleGuard(r);

  const match = await _findClient(db, identifier);
  if (!match) throw new HttpsError("not-found", "No account found with that email or phone number.");

  const status = match.data.status || "Approved";
  if (status !== "Approved") {
    throw new HttpsError("failed-precondition", "Account pending approval.", { pending: true });
  }

  const authRef = db.collection("client_auth").doc(match.id);
  const authDoc = await authRef.get();
  const storedHash = (authDoc.exists && authDoc.data().hash) ? authDoc.data().hash : null;
  let ok = false;

  if (storedHash) ok = await bcrypt.compare(String(password), storedHash);

  if (!ok && match.data.password && String(match.data.password) === String(password)) {
    ok = true;
    const hash = await bcrypt.hash(String(password), 10);
    await authRef.set({ hash, migratedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await db.collection("clients").doc(match.id)
      .update({ password: admin.firestore.FieldValue.delete(), hasPassword: true });
  }

  if (!ok && !storedHash && !match.data.password) {
    throw new HttpsError("failed-precondition", "No password is set for this account.", { clientId: match.id, noPassword: true });
  }
  if (!ok) {
    await Promise.all(tRefs.map((r, i) => throttleFailure(r, i === 0 ? THROTTLE_MAX : THROTTLE_IP_MAX)));
    throw new HttpsError("unauthenticated", "Incorrect email/phone or password.");
  }
  await Promise.all(tRefs.map(throttleClear));

  const c = Object.assign({ id: match.id }, match.data);
  delete c.password;
  const authToken = await mintPortalToken("client", match.id, match.data);
  return {
    success: true,
    client: c,
    authToken,
    passwordResetRequired: !!match.data.passwordResetRequired,
  };
});

/**
 * Reads SMTP_URL defensively.
 *
 * Google shows an app password as "abcd efgh ijkl mnop". Pasted with those
 * spaces — or with surrounding quotes, or a trailing newline — the URL parses
 * into a different credential and Gmail answers 535 BadCredentials, which
 * looks identical to a wrong password. A valid smtps:// URL contains no
 * whitespace, so stripping it is always safe.
 *
 * Logs the host and username it ended up with (never the password) so a
 * rejection can be told apart from a malformed secret.
 */
function readSmtpUrl() {
  let raw = String(smtpUrl.value() || "").trim();
  if (!raw || raw === "unset") return null;
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    raw = raw.slice(1, -1);
  }
  const cleaned = raw.replace(/\s+/g, "");
  try {
    const u = new URL(cleaned);
    console.log("SMTP config: protocol=%s host=%s port=%s user=%s passLen=%d",
      u.protocol, u.hostname, u.port || "(default)",
      decodeURIComponent(u.username || "(none)"), (u.password || "").length);
  } catch (e) {
    console.error("SMTP_URL is not a valid URL after cleaning:", e.message);
    return null;
  }
  return cleaned;
}

/**
 * Sends a transactional email on behalf of the business.
 *
 * admin.html used to add a document to a `mail` collection, which is the
 * Firebase "Trigger Email" extension's interface — but no extension is
 * installed on this project, so those writes did nothing and corporate
 * customers never received their portal login. The FormSubmit call beside it
 * only ever notified info@seacoastrvip.com, not the customer.
 *
 * Admin-only: this can send mail as the business, so it must never be open.
 */
exports.sendAdminEmail = onCall({ secrets: [smtpUrl] }, async (request) => {
  requireAdmin(request);
  const { to, subject, text, html } = request.data || {};
  if (!to || !subject || !(text || html)) {
    throw new HttpsError("invalid-argument", "Need a recipient, a subject and a body.");
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(to).trim())) {
    throw new HttpsError("invalid-argument", "That recipient address is not valid.");
  }

  const url = readSmtpUrl();
  if (!url || url === "unset") {
    throw new HttpsError(
      "failed-precondition",
      "Email is not configured yet. Set the SMTP_URL secret and redeploy."
    );
  }

  const nodemailer = require("nodemailer");
  try {
    const transport = nodemailer.createTransport(url);
    const info = await transport.sendMail({
      from: "Seacoast RVIP <info@seacoastrvip.com>",
      replyTo: "info@seacoastrvip.com",
      to: String(to).trim(),
      subject: String(subject),
      text: text ? String(text) : undefined,
      html: html ? String(html) : undefined,
    });
    return { success: true, messageId: info.messageId || null };
  } catch (e) {
    console.error("sendAdminEmail failed:", e.message);
    throw new HttpsError("internal", "The message could not be sent: " + e.message);
  }
});

/**
 * Looks a booking up by its RVIP code for the payment page.
 *
 * payment.html used an anonymous where('code','==',...) query, which the
 * owner-only bookings rule denies — the payer has a code, not a session. The
 * code is the bearer credential here, exactly as it is on the printed
 * confirmation, and only the fields the payment screen renders come back.
 */
exports.bookingByCode = onCall(async (request) => {
  const raw = String((request.data || {}).code || "").trim();
  if (!raw) throw new HttpsError("invalid-argument", "Missing booking code.");

  const db = admin.firestore();
  // Codes have been stored both bare and RVIP-prefixed, in either case.
  const bare = raw.replace(/^RVIP-/i, "");
  const candidates = [...new Set([raw, raw.toUpperCase(), bare, bare.toUpperCase(),
    "RVIP-" + bare, "RVIP-" + bare.toUpperCase()])];

  for (const c of candidates) {
    const snap = await db.collection("bookings").where("code", "==", c).limit(1).get();
    if (snap.empty) continue;
    const doc = snap.docs[0];
    const b = doc.data() || {};
    return {
      found: true,
      booking: {
        id: doc.id,
        code: b.code || c,
        name: b.name || b.clientName || "",
        service: b.service || "",
        date: b.date || "",
        time: b.time || "",
        pickup: b.pickup || "",
        destination: b.destination || "",
        vehicle: b.vehicle || "",
        passengers: b.passengers || "1",
        price: parseFloat(b.price) || 0,
        status: b.status || "Pending",
      },
    };
  }
  return { found: false, booking: null };
});

/**
 * Records that an ACH payment was initiated for a booking. payment.html wrote
 * this straight to Firestore while unauthenticated, which the bookings rule
 * now refuses. Requires the booking's own code, so a caller cannot flip the
 * status of a booking they do not hold a code for.
 */
exports.markBookingAchInitiated = onCall(async (request) => {
  const { bookingId, code } = request.data || {};
  if (!bookingId || !code) throw new HttpsError("invalid-argument", "Missing booking or code.");

  const db = admin.firestore();
  const ref = db.collection("bookings").doc(String(bookingId));
  const doc = await ref.get();
  if (!doc.exists) throw new HttpsError("not-found", "Booking not found.");

  const stored = String((doc.data() || {}).code || "").replace(/^RVIP-/i, "").toUpperCase();
  const given = String(code).replace(/^RVIP-/i, "").toUpperCase();
  if (!stored || stored !== given) {
    throw new HttpsError("permission-denied", "That code does not match this booking.");
  }

  await ref.update({
    status: "Confirmed",
    paymentMethod: "Bank ACH",
    paymentNote: "ACH initiated — pending settlement",
  });
  return { success: true };
});

/**
 * One-time: stamps clientId / corporateAccountId onto bookings that predate
 * those fields, by matching the booking's email or phone against the clients
 * and corporate_accounts collections.
 *
 * Until every booking carries an owner, the bookings rule cannot be narrowed
 * past "any signed-in caller" — the portals would simply stop finding the
 * older trips. Call with { confirm: 'BACKFILL' }; it is safe to re-run and
 * reports how many documents still have no owner.
 */
exports.backfillBookingOwners = onCall({ timeoutSeconds: 540 }, async (request) => {
  if (!request.data || request.data.confirm !== "BACKFILL") {
    throw new HttpsError("invalid-argument", "Pass { confirm: 'BACKFILL' } to run this.");
  }
  const db = admin.firestore();
  const last10 = (v) => String(v || "").replace(/\D/g, "").slice(-10);
  const norm = (v) => String(v || "").trim().toLowerCase();

  // Both collections are small enough to hold in memory.
  const byEmail = new Map();
  const byPhone = new Map();
  const clientsSnap = await db.collection("clients").get();
  clientsSnap.forEach((d) => {
    const c = d.data() || {};
    if (c.email) byEmail.set(norm(c.email), d.id);
    const p = last10(c.phone);
    if (p.length === 10) byPhone.set(p, d.id);
  });

  const corps = [];
  const corpSnap = await db.collection("corporate_accounts").get();
  corpSnap.forEach((d) => {
    const a = d.data() || {};
    const emails = new Set();
    const phones = new Set();
    if (a.contactEmail) emails.add(norm(a.contactEmail));
    if (last10(a.contactPhone).length === 10) phones.add(last10(a.contactPhone));
    (a.members || []).forEach((m) => {
      if (m && m.email) emails.add(norm(m.email));
      if (m && last10(m.phone).length === 10) phones.add(last10(m.phone));
    });
    corps.push({ id: a.id || d.id, company: a.company || "", emails, phones });
  });

  let scanned = 0, stampedClient = 0, stampedCorp = 0, stillUnowned = 0;
  let cursor = null;
  const PAGE = 400;

  for (;;) {
    let q = db.collection("bookings").orderBy(admin.firestore.FieldPath.documentId()).limit(PAGE);
    if (cursor) q = q.startAfter(cursor);
    const page = await q.get();
    if (page.empty) break;
    cursor = page.docs[page.docs.length - 1];

    let batch = db.batch();
    let writes = 0;

    for (const doc of page.docs) {
      scanned++;
      const b = doc.data() || {};
      const upd = {};
      const email = norm(b.email);
      const phone = last10(b.phone);

      if (!b.clientId) {
        const hit = (email && byEmail.get(email)) || (phone.length === 10 && byPhone.get(phone));
        if (hit) { upd.clientId = hit; stampedClient++; }
      }
      if (!b.corporateAccountId) {
        const acc = corps.find((c) => (email && c.emails.has(email)) || (phone.length === 10 && c.phones.has(phone)));
        if (acc) {
          upd.corporateAccountId = acc.id;
          if (!b.corporateCompany && acc.company) upd.corporateCompany = acc.company;
          stampedCorp++;
        }
      }
      if (Object.keys(upd).length) { batch.update(doc.ref, upd); writes++; }
      if (!b.clientId && !b.corporateAccountId && !upd.clientId && !upd.corporateAccountId) stillUnowned++;

      if (writes >= 400) { await batch.commit(); batch = db.batch(); writes = 0; }
    }
    if (writes) await batch.commit();
    if (page.size < PAGE) break;
  }

  return { success: true, scanned, stampedClient, stampedCorp, stillUnowned };
});

/**
 * Links a freshly created booking to a corporate account when the booker's
 * phone matches the account's contact or one of its members.
 *
 * schedule.html used to do this by downloading every Approved/Active corporate
 * account — company names, contacts and whole member lists — into an anonymous
 * browser to compare phone numbers. Here the comparison happens server-side and
 * the caller learns only whether a link was made.
 */
exports.linkBookingToCorporate = onCall(async (request) => {
  const { bookingId, phone } = request.data || {};
  if (!bookingId || !phone) throw new HttpsError("invalid-argument", "Missing booking or phone.");
  const digits = String(phone).replace(/\D/g, "").slice(-10);
  if (digits.length !== 10) return { linked: false };

  const db = admin.firestore();
  const snap = await db.collection("corporate_accounts")
    .where("status", "in", ["Approved", "Active"]).get();

  const last10 = (v) => String(v || "").replace(/\D/g, "").slice(-10);
  for (const doc of snap.docs) {
    const acc = doc.data() || {};
    let hit = last10(acc.contactPhone) === digits;
    if (!hit) hit = (acc.members || []).some((m) => last10(m && m.phone) === digits);
    if (hit) {
      await db.collection("bookings").doc(String(bookingId)).update({
        corporateAccountId: acc.id || doc.id,
        corporateCompany: acc.company || "",
      });
      return { linked: true };
    }
  }
  return { linked: false };
});

// The only client fields the website is allowed to learn about an account.
// Everything else on the document — address, balance, payment history, admin
// notes — stays server-side.
function publicClientView(id, d) {
  const data = d || {};
  return {
    id,
    name: data.name || "",
    email: data.email || "",
    phone: data.phone || "",
    status: data.status || "Approved",
    hasPassword: !!(data.hasPassword || data.password),
    passwordResetRequired: !!data.passwordResetRequired,
    corporateAccountId: data.corporateAccountId || null,
    firebaseUid: data.firebaseUid || null,
  };
}

/**
 * Looks a client up by email or phone, or by the caller's own Firebase uid.
 *
 * account.html used to run these queries straight against Firestore, which is
 * why `clients` had to be readable by anyone — and that made the whole customer
 * list (names, emails, phones, addresses, balances) public to anyone holding
 * the API key from the page source. Going through here means the caller learns
 * only about the identifier they already supplied, and only the fields in
 * publicClientView.
 */
exports.clientLookup = onCall(async (request) => {
  const db = admin.firestore();
  const { identifier, byUid } = request.data || {};

  if (byUid) {
    if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
    const snap = await db.collection("clients")
      .where("firebaseUid", "==", request.auth.uid).limit(1).get();
    if (snap.empty) return { found: false, client: null };
    return { found: true, client: publicClientView(snap.docs[0].id, snap.docs[0].data()) };
  }

  if (!identifier) throw new HttpsError("invalid-argument", "Missing email or phone.");
  const match = await _findClient(db, identifier);
  if (!match) return { found: false, client: null };
  return { found: true, client: publicClientView(match.id, match.data) };
});

/**
 * Issues a portal session for someone already signed in by email link, SMS or
 * a social provider. Those flows produce a Firebase Auth user with no portal
 * claims, so without this their dashboard would load but their trips — which
 * live under clients/{clientId}/trips — would come back empty.
 *
 * The client is resolved only from properties of the *verified* token (its
 * email, its phone number, or a firebaseUid already recorded on the record),
 * so this cannot be used to obtain a session for somebody else's account.
 */
exports.clientPortalSession = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const db = admin.firestore();
  const token = request.auth.token || {};
  const email = String(token.email || "").trim().toLowerCase();
  const phone = String(token.phone_number || "").replace(/\D/g, "").slice(-10);

  let match = null;
  if (email) match = await _findClient(db, email);
  if (!match && phone.length === 10) match = await _findClient(db, phone);
  if (!match) {
    const snap = await db.collection("clients")
      .where("firebaseUid", "==", request.auth.uid).limit(1).get();
    if (!snap.empty) match = { id: snap.docs[0].id, data: snap.docs[0].data() };
  }
  if (!match) throw new HttpsError("not-found", "No account matches this sign-in.");

  const authToken = await mintPortalToken("client", match.id, match.data);
  if (!authToken) throw new HttpsError("internal", "Could not issue a portal session.");
  return { success: true, clientId: match.id, authToken };
});

/**
 * Prepares a client for the email-link setup flow: records an email address if
 * the account has none on file, and flags that the next sign-in must set a
 * password.
 *
 * account.html used to do both of these as direct, unauthenticated Firestore
 * writes, which meant anyone could set the email on any passwordless client
 * record and then have a sign-in link sent to it. Doing it here lets the
 * `clients` collection refuse anonymous writes.
 */
exports.clientRequestEmailSetup = onCall(async (request) => {
  const { identifier, email } = request.data || {};
  if (!identifier) throw new HttpsError("invalid-argument", "Missing email or phone.");
  const db = admin.firestore();

  const match = await _findClient(db, identifier);
  if (!match) throw new HttpsError("not-found", "No account found with that email or phone number.");

  const update = { passwordResetRequired: true };
  // Only ever fill in a missing address — never overwrite one, or this would
  // be the account-takeover path it replaces.
  const wanted = String(email || "").trim().toLowerCase();
  if (!match.data.email && wanted) {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(wanted)) {
      throw new HttpsError("invalid-argument", "That email address is not valid.");
    }
    update.email = wanted;
  }
  await db.collection("clients").doc(match.id).update(update);
  return { success: true, clientId: match.id, email: update.email || match.data.email || null };
});

/**
 * Sets a personal client's password, stored only as a bcrypt hash.
 * Authorised by the current password, or by a verified Firebase Auth session
 * (the email-link and SMS setup flows sign the user in before reaching here).
 */
exports.clientSetPassword = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  const { clientId, currentPassword, newPassword } = request.data || {};
  if (!clientId || !newPassword) throw new HttpsError("invalid-argument", "Missing data.");
  if (String(newPassword).length < 6) throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");

  const db = admin.firestore();
  const ref = db.collection("clients").doc(clientId);
  const doc = await ref.get();
  if (!doc.exists) throw new HttpsError("not-found", "Account not found.");
  const data = doc.data();

  const authRef = db.collection("client_auth").doc(clientId);
  const authDoc = await authRef.get();
  const hasHash = authDoc.exists && !!authDoc.data().hash;
  const hasPlain = !!data.password;
  const verifiedSession = !!request.auth;

  if ((hasHash || hasPlain) && !verifiedSession) {
    let ok = false;
    if (hasHash) ok = await bcrypt.compare(String(currentPassword || ""), authDoc.data().hash);
    else ok = String(currentPassword || "") === String(data.password);
    if (!ok) throw new HttpsError("permission-denied", "Current password is incorrect.");
  }
  if (!hasHash && !hasPlain && !verifiedSession) {
    // Claiming a passwordless account requires a verified email or phone first.
    throw new HttpsError("permission-denied", "Verify your email or phone before setting a password.");
  }

  const hash = await bcrypt.hash(String(newPassword), 10);
  await authRef.set({ hash, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await ref.update({
    password: admin.firestore.FieldValue.delete(),
    hasPassword: true,
    passwordResetRequired: false,
    updatedAt: new Date().toISOString(),
  });
  return { success: true };
});

/** Admin-set temporary password for a personal client. Hash only. */
exports.clientSetTempPassword = onCall(async (request) => {
  requireAdmin(request);
  const bcrypt = require("bcryptjs");
  const { clientId, password, status } = request.data || {};
  if (!clientId) throw new HttpsError("invalid-argument", "Missing clientId.");
  if (password && String(password).length < 6) {
    throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");
  }
  const db = admin.firestore();
  const ref = db.collection("clients").doc(clientId);
  if (!(await ref.get()).exists) throw new HttpsError("not-found", "Account not found.");

  const tempPwd = password ? String(password) : "RVIP" + Math.random().toString(36).slice(-6).toUpperCase();
  const hash = await bcrypt.hash(tempPwd, 10);
  await db.collection("client_auth").doc(clientId)
    .set({ hash, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  const upd = {
    password: admin.firestore.FieldValue.delete(),
    hasPassword: true,
    passwordResetRequired: true,
    updatedAt: new Date().toISOString(),
  };
  if (status) upd.status = status;
  await ref.update(upd);
  return { success: true, tempPassword: tempPwd };
});

/**
 * One-time migration for the clients collection. Same contract as
 * migrateCorporatePasswords: hashes every plaintext password into client_auth
 * and deletes the field. Confirm `remaining` comes back 0.
 */
exports.migrateClientPasswords = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  if (!request.data || request.data.confirm !== "MIGRATE") {
    throw new HttpsError("invalid-argument", "Pass { confirm: 'MIGRATE' } to run this migration.");
  }
  const db = admin.firestore();
  const snap = await db.collection("clients").get();

  let hashed = 0, alreadyHashed = 0, noPassword = 0;
  for (const doc of snap.docs) {
    const plain = doc.data().password;
    if (!plain) { noPassword++; continue; }
    const authRef = db.collection("client_auth").doc(doc.id);
    const authDoc = await authRef.get();
    if (!(authDoc.exists && authDoc.data().hash)) {
      const hash = await bcrypt.hash(String(plain), 10);
      await authRef.set({ hash, migratedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      hashed++;
    } else {
      alreadyHashed++;
    }
    await doc.ref.update({ password: admin.firestore.FieldValue.delete(), hasPassword: true });
  }

  const after = await db.collection("clients").get();
  const remaining = after.docs.filter((d) => !!d.data().password).length;
  return { success: true, total: snap.size, hashed, alreadyHashed, noPassword, remaining };
});
