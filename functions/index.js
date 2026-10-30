const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
admin.initializeApp();

const stripeSecret = defineSecret("STRIPE_SECRET");

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
exports.resetCorpPassword = onCall(async (request) => {
  const { email, newPassword } = request.data;
  if (!email || !newPassword) throw new HttpsError("invalid-argument", "Missing email or password");
  if (newPassword.length < 6)  throw new HttpsError("invalid-argument", "Password must be at least 6 characters");

  const db = admin.firestore();
  const snap = await db.collection("corporate_accounts")
    .where("status", "in", ["Approved", "Active"])
    .get();

  let found = null;
  snap.forEach(d => {
    if ((d.data().contactEmail || "").toLowerCase().trim() === email.toLowerCase()) found = d;
  });

  if (!found) throw new HttpsError("not-found", "No active corporate account found with that email");

  await found.ref.update({ password: newPassword, passwordResetRequired: false });
  // Remove any stale hash so the next login re-syncs it from this new password.
  await db.collection("corporate_auth").doc(found.id).delete().catch(() => {});
  return { success: true };
});

/**
 * Verifies a corporate account email exists in Firestore (admin SDK bypasses
 * client-side security rules) and ensures a matching Firebase Auth user exists
 * so sendPasswordResetEmail can deliver a reset link.
 */
exports.ensureCorpAuthAccount = onCall(async (request) => {
  const { email } = request.data;
  if (!email) throw new HttpsError("invalid-argument", "Missing email");

  const db = admin.firestore();
  const snap = await db.collection("corporate_accounts")
    .where("status", "in", ["Approved", "Active"])
    .get();

  let found = null;
  snap.forEach(d => {
    if ((d.data().contactEmail || "").toLowerCase().trim() === email.toLowerCase()) found = d;
  });
  if (!found) throw new HttpsError("not-found", "No active corporate account found with that email");

  // Ensure a Firebase Auth user exists so sendPasswordResetEmail has a target.
  // We silently absorb auth errors so the function never returns "internal" —
  // if the user already exists under a different lookup path, that's fine.
  let authExists = false;
  try {
    await admin.auth().getUserByEmail(email);
    authExists = true;
  } catch (e) {
    if (e.code !== "auth/user-not-found") {
      // Unexpected lookup error — log it but don't crash; fall through to create
      console.error("ensureCorpAuthAccount getUserByEmail:", e.code, e.message);
    }
  }

  if (!authExists) {
    try {
      const tempPwd = Math.random().toString(36).slice(-8) + "Aa1!";
      await admin.auth().createUser({ email, password: tempPwd });
    } catch (createErr) {
      // auth/email-already-exists means a race condition — user was created between
      // our check and create call, which is fine
      if (createErr.code !== "auth/email-already-exists") {
        throw new HttpsError("internal", "Could not prepare account: " + createErr.message);
      }
    }
  }

  return { success: true };
});

// ─────────────────────────────────────────────────────────────────────────────
//  SECURE CORPORATE AUTH (Phase 1)
//  Passwords are verified/stored server-side as bcrypt hashes in the locked
//  `corporate_auth/{accountId}` collection (clients can never read it). The
//  login function falls back to the old plaintext password and upgrades it to a
//  hash on the fly, so no one is locked out during the migration.
// ─────────────────────────────────────────────────────────────────────────────

// Find an Approved/Active corporate account by email/phone (contact or member).
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
 * Corporate portal login. Verifies the password server-side (bcrypt hash, with a
 * one-time plaintext fallback that upgrades to a hash). Returns the sanitized
 * account (no password) and whether a reset is required.
 */
exports.corporateLogin = onCall(async (request) => {
  const bcrypt = require("bcryptjs");
  const { identifier, password } = request.data || {};
  if (!identifier || !password) throw new HttpsError("invalid-argument", "Missing email/phone or password.");
  const db = admin.firestore();

  const match = await _findCorpAccount(db, identifier);
  if (!match) throw new HttpsError("unauthenticated", "Incorrect email/phone or password.");

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
  //    (admin Portal Access / resetCorpPassword). On a match, (re)write the hash so
  //    it stays in sync with the current password.
  if (!ok && match.data.password && String(match.data.password) === String(password)) {
    ok = true;
    const hash = await bcrypt.hash(String(password), 10);
    await authRef.set({ hash, migratedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  }
  // 3) Nothing to check against at all.
  if (!ok && !storedHash && !match.data.password) {
    throw new HttpsError("failed-precondition", "No password is set for this account.");
  }

  if (!ok) throw new HttpsError("unauthenticated", "Incorrect email/phone or password.");

  const acc = Object.assign({ id: match.id }, match.data);
  delete acc.password;
  return { success: true, account: acc, passwordResetRequired: !!match.data.passwordResetRequired };
});

/**
 * Sets a NEW corporate password (hashed). Requires the current password unless
 * none is set yet. Clears the legacy plaintext field and the reset flag.
 */
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

  // If a password already exists, require the correct current one.
  if (hasHash || hasPlain) {
    let ok = false;
    if (hasHash) ok = await bcrypt.compare(String(currentPassword || ""), authDoc.data().hash);
    else ok = String(currentPassword || "") === String(data.password);
    if (!ok) throw new HttpsError("permission-denied", "Current password is incorrect.");
  }

  const hash = await bcrypt.hash(String(newPassword), 10);
  await authRef.set({ hash, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await ref.update({
    password: admin.firestore.FieldValue.delete(),
    passwordResetRequired: false,
    updatedAt: new Date().toISOString(),
  });
  return { success: true };
});
