const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

// STRIPE VERSION 1 CALLABLES
const stripeSecret = "STRIPE_SECRET"; // In v1 we use .runWith({ secrets: [...] })

/**
 * Ensures a corporate account has a Stripe Customer ID.
 */
exports.getStripeCustomer = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { accountId, email, company } = data;
  
  if (!accountId) throw new functions.https.HttpsError("invalid-argument", "Missing Account ID");

  let accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  let accountDoc = await accountRef.get();

  // If not in corporate, check clients
  if (!accountDoc.exists) {
    accountRef = admin.firestore().collection("clients").doc(accountId);
    accountDoc = await accountRef.get();
  }

  if (!accountDoc.exists) throw new functions.https.HttpsError("not-found", "Account not found");

  const accountData = accountDoc.data();
  if (accountData.stripeCustomerId) return { customerId: accountData.stripeCustomerId };

  const customer = await stripe.customers.create({
    email: email || accountData.contactEmail,
    name: company || accountData.company,
    metadata: { accountId: accountId }
  });

  await accountRef.update({ stripeCustomerId: customer.id });
  return { customerId: customer.id };
});

/**
 * Generates a SetupIntent client secret.
 */
exports.createSetupIntent = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { customerId } = data;
  if (!customerId) throw new functions.https.HttpsError("invalid-argument", "Missing Customer ID");

  const setupIntent = await stripe.setupIntents.create({
    customer: customerId,
    payment_method_types: ["card"],
  });

  return { clientSecret: setupIntent.client_secret };
});

/**
 * Charges the saved payment method.
 */
exports.chargeSavedCard = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { accountId, amount } = data;

  if (!accountId || !amount || amount <= 0) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid account or amount");
  }

  let accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  let accountDoc = await accountRef.get();
  if(!accountDoc.exists) {
    accountRef = admin.firestore().collection("clients").doc(accountId);
    accountDoc = await accountRef.get();
  }
  if (!accountDoc.exists) throw new functions.https.HttpsError("not-found", "Account not found");

  const accountData = accountDoc.data();
  const { stripeCustomerId: customerId, stripePaymentMethodId: paymentMethodId } = accountData;

  if (!customerId || !paymentMethodId) {
    throw new functions.https.HttpsError("failed-precondition", "No saved payment method found");
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: "usd",
      customer: customerId,
      payment_method: paymentMethodId,
      off_session: true,
      confirm: true,
    });

    if (paymentIntent.status === "succeeded") {
      // 1. Update Account Balance
      await accountRef.update({
        balance: 0,
        lastPaymentDate: admin.firestore.FieldValue.serverTimestamp(),
        lastPaymentAmount: amount,
        lastPaymentId: paymentIntent.id
      });

      // 2. Mark all 'Confirmed' bookings as 'Completed'
      try {
        const bookingsSnap = await admin.firestore().collection("bookings")
          .where("corporateAccountId", "==", accountId)
          .where("status", "==", "Confirmed")
          .get();
        
        const batch = admin.firestore().batch();
        bookingsSnap.forEach(doc => {
          batch.update(doc.ref, { status: "Completed", updatedAt: new Date().toISOString() });
        });
        await batch.commit();
      } catch (e) {
        console.warn("Failed to update bookings after payment:", e.message);
      }

      return { success: true, paymentIntentId: paymentIntent.id };
    }
    return { success: false, status: paymentIntent.status };
  } catch (error) {
    console.error("chargeSavedCard Error:", error);
    throw new functions.https.HttpsError("internal", error.message);
  }
});

/**
 * Saves PM ID to Firestore.
 */
exports.savePaymentMethod = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { accountId, paymentMethodId } = data;
  if (!accountId || !paymentMethodId) throw new functions.https.HttpsError("invalid-argument", "Missing data");

  let accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  let accountDoc = await accountRef.get();
  if(!accountDoc.exists) {
    accountRef = admin.firestore().collection("clients").doc(accountId);
    accountDoc = await accountRef.get();
  }
  if (!accountDoc.exists) throw new functions.https.HttpsError("not-found", "Account not found");

  const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);

  await accountRef.update({
    stripePaymentMethodId: paymentMethodId,
    cardBrand: paymentMethod.card.brand,
    cardLast4: paymentMethod.card.last4
  });

  return { success: true };
});
