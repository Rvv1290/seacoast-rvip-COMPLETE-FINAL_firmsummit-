const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
admin.initializeApp();

// Define the secret - replace STRIPE_SECRET with your key when prompted by firebase deploy
const stripeSecret = defineSecret("STRIPE_SECRET");

/**
 * Ensures a corporate account has a Stripe Customer ID.
 */
exports.getStripeCustomer = onCall({ 
  secrets: [stripeSecret],
  invoker: "public" 
}, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, email, company } = request.data;
  
  if (!accountId) throw new HttpsError("invalid-argument", "Missing Account ID");

  const accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  const accountDoc = await accountRef.get();

  if (!accountDoc.exists) throw new HttpsError("not-found", "Account not found");

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
exports.createSetupIntent = onCall({ 
  secrets: [stripeSecret],
  invoker: "public"
}, async (request) => {
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
 * Charges the saved payment method.
 */
exports.chargeSavedCard = onCall({ 
  secrets: [stripeSecret],
  invoker: "public"
}, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, amount } = request.data;

  if (!accountId || !amount || amount <= 0) {
    throw new HttpsError("invalid-argument", "Invalid account or amount");
  }

  const accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  const accountDoc = await accountRef.get();
  if (!accountDoc.exists) throw new HttpsError("not-found", "Account not found");

  const accountData = accountDoc.data();
  const { stripeCustomerId: customerId, stripePaymentMethodId: paymentMethodId } = accountData;

  if (!customerId || !paymentMethodId) {
    throw new HttpsError("failed-precondition", "No saved payment method found");
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
    throw new HttpsError("internal", error.message);
  }
});

/**
 * Saves PM ID to Firestore.
 */
exports.savePaymentMethod = onCall({ 
  secrets: [stripeSecret],
  invoker: "public"
}, async (request) => {
  const stripe = require("stripe")(stripeSecret.value());
  const { accountId, paymentMethodId } = request.data;
  if (!accountId || !paymentMethodId) throw new HttpsError("invalid-argument", "Missing data");

  const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);

  await admin.firestore().collection("corporate_accounts").doc(accountId).update({
    stripePaymentMethodId: paymentMethodId,
    cardBrand: paymentMethod.card.brand,
    cardLast4: paymentMethod.card.last4
  });

  return { success: true };
});
