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

  if (data.stripeCustomerId) return { customerId: data.stripeCustomerId };

  const customer = await stripe.customers.create({
    email: email || data.contactEmail || data.email || "",
    name: company || data.company || data.name || "",
    metadata: { accountId },
  });

  await ref.update({ stripeCustomerId: customer.id });
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

  const paymentIntent = await stripe.paymentIntents.create(piParams);
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
