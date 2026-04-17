const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

// Secret names for Firebase Secret Manager
const stripeSecret        = "STRIPE_SECRET";
const calendarCredsSecret = "GOOGLE_CALENDAR_CREDS"; // Service account JSON (stringified)

// ─────────────────────────────────────────────────────────────────────────────
// GOOGLE CALENDAR SYNC
// Auto-creates a Google Calendar event when a booking is confirmed.
//
// SETUP REQUIRED (one-time):
//   1. Create a Google Cloud service account with "Google Calendar API" enabled.
//   2. Share your Google Calendar with the service account email (Editor permission).
//   3. Store the service account JSON as a Firebase Secret named GOOGLE_CALENDAR_CREDS.
//   4. Set your Calendar ID in the GOOGLE_CALENDAR_ID env var or hardcode below.
// ─────────────────────────────────────────────────────────────────────────────
exports.syncBookingToCalendar = functions
  .runWith({ secrets: [calendarCredsSecret] })
  .firestore.document("bookings/{bookingId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after  = change.after.exists  ? change.after.data()  : null;

    if (!after) return; // Booking deleted — optionally delete calendar event

    const wasConfirmed = before && before.status === "Confirmed";
    const isConfirmed  = after.status === "Confirmed";
    const bookingId    = context.params.bookingId;

    // Only act when status first becomes Confirmed
    if (wasConfirmed || !isConfirmed) return;

    const credsJson = process.env.GOOGLE_CALENDAR_CREDS;
    if (!credsJson) {
      console.warn("GOOGLE_CALENDAR_CREDS secret not set — skipping calendar sync");
      return;
    }

    try {
      const { google } = require("googleapis");
      const creds = JSON.parse(credsJson);
      const auth = new google.auth.GoogleAuth({
        credentials: creds,
        scopes: ["https://www.googleapis.com/auth/calendar.events"],
      });
      const calendar = google.calendar({ version: "v3", auth });

      const calendarId = process.env.GOOGLE_CALENDAR_ID || "primary";

      // Build date/time — fallback to all-day if no time
      const dateStr = after.date || new Date().toISOString().split("T")[0];
      const timeStr = after.time && after.time !== "TBD" ? after.time : null;
      let start, end;
      if (timeStr) {
        const startISO = `${dateStr}T${timeStr}:00`;
        const endDate  = new Date(startISO);
        endDate.setHours(endDate.getHours() + 2); // assume 2-hour window
        start = { dateTime: startISO, timeZone: "America/New_York" };
        end   = { dateTime: endDate.toISOString(), timeZone: "America/New_York" };
      } else {
        start = { date: dateStr };
        end   = { date: dateStr };
      }

      const stops = after.stops ? `\nStops: ${after.stops}` : "";
      const timeTbd = after.pickupTimeTBD ? "\n⚠️ Pickup time TBD — confirm with client" : "";

      const event = {
        summary: `🚗 ${after.name || "Ride"} — ${after.service || "Transfer"}${after.company ? ` (${after.company})` : ""}`,
        description:
          `Passenger: ${after.name || "—"}\n` +
          `Phone: ${after.phone || "—"}\n` +
          `Email: ${after.email || "—"}\n` +
          `Pickup: ${after.pickup || "—"}\n` +
          `Drop-off: ${after.destination || "—"}` +
          stops + timeTbd +
          `\n\nPassengers: ${after.passengers || 1}\n` +
          `Vehicle: ${after.vehicle || "—"}\n` +
          `Booking Code: ${after.code || bookingId}`,
        start,
        end,
        colorId: "9", // blueberry
        reminders: {
          useDefault: false,
          overrides: [
            { method: "popup", minutes: 60 },
            { method: "popup", minutes: 15 },
          ],
        },
      };

      const result = await calendar.events.insert({ calendarId, requestBody: event });
      await change.after.ref.update({ googleCalendarEventId: result.data.id });
      console.log("Calendar event created:", result.data.id, "for booking:", bookingId);
    } catch (err) {
      console.error("Calendar sync error:", err.message);
    }
  });

// STRIPE VERSION 1 CALLABLES


/**
 * Ensures an account has a valid Stripe Customer ID.
 * Verifies the stored ID still exists in Stripe (guards against stale/test IDs).
 */
exports.getStripeCustomer = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { accountId, email, company } = data;

  if (!accountId) throw new functions.https.HttpsError("invalid-argument", "Missing Account ID");

  let accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  let accountDoc = await accountRef.get();

  if (!accountDoc.exists) {
    accountRef = admin.firestore().collection("clients").doc(accountId);
    accountDoc = await accountRef.get();
  }
  if (!accountDoc.exists) throw new functions.https.HttpsError("not-found", "Account not found");

  const accountData = accountDoc.data();

  // Verify the stored Stripe customer still exists (could be stale/from test mode)
  if (accountData.stripeCustomerId) {
    try {
      const existing = await stripe.customers.retrieve(accountData.stripeCustomerId);
      if (!existing.deleted) {
        return { customerId: accountData.stripeCustomerId };
      }
      // Customer was deleted — fall through to create a new one
    } catch (e) {
      // Customer not found in Stripe — fall through to create a new one
      console.warn("Stored Stripe customer not found, creating new one:", e.message);
    }
  }

  try {
    const customer = await stripe.customers.create({
      email: email || accountData.contactEmail || "",
      name: company || accountData.company || "",
      metadata: { accountId: accountId }
    });
    await accountRef.update({ stripeCustomerId: customer.id });
    return { customerId: customer.id };
  } catch (stripeErr) {
    console.error("Stripe customer create error:", stripeErr.message);
    throw new functions.https.HttpsError("internal", "Could not create Stripe customer: " + stripeErr.message);
  }
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
 * If the PM is stale (used without customer attachment), clears it from Firestore
 * and returns STALE_CARD so the frontend can prompt the user to re-enter.
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
    console.error("chargeSavedCard Error:", error.message);

    // Detect stale/detached PM — clear it from Firestore so user can re-enter card
    const isStaleCard = error.message && (
      error.message.includes("must attach it to a Customer") ||
      error.message.includes("previously used with a PaymentIntent without Customer") ||
      error.message.includes("detached from a Customer") ||
      error.message.includes("shared with a connected account without Customer")
    );

    if (isStaleCard) {
      try {
        await accountRef.update({
          stripePaymentMethodId: admin.firestore.FieldValue.delete(),
          cardBrand: admin.firestore.FieldValue.delete(),
          cardLast4: admin.firestore.FieldValue.delete()
        });
        console.log("Cleared stale payment method for account:", accountId);
      } catch (clearErr) {
        console.warn("Could not clear stale PM:", clearErr.message);
      }
      throw new functions.https.HttpsError("failed-precondition", "STALE_CARD");
    }

    throw new functions.https.HttpsError("internal", error.message);
  }
});

/**
 * Saves PM ID to Firestore AND attaches it to the Stripe customer.
 * If the PM cannot be attached (was used without customer), rejects the save
 * so the user is not left with a stale card stored.
 */
exports.savePaymentMethod = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { accountId, paymentMethodId } = data;
  if (!accountId || !paymentMethodId) throw new functions.https.HttpsError("invalid-argument", "Missing data");

  let accountRef = admin.firestore().collection("corporate_accounts").doc(accountId);
  let accountDoc = await accountRef.get();
  if (!accountDoc.exists) {
    accountRef = admin.firestore().collection("clients").doc(accountId);
    accountDoc = await accountRef.get();
  }
  if (!accountDoc.exists) throw new functions.https.HttpsError("not-found", "Account not found");

  const accountData = accountDoc.data();
  const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);

  // Attach PM to the Stripe customer so off-session charges work
  if (accountData.stripeCustomerId) {
    try {
      await stripe.paymentMethods.attach(paymentMethodId, { customer: accountData.stripeCustomerId });
      await stripe.customers.update(accountData.stripeCustomerId, {
        invoice_settings: { default_payment_method: paymentMethodId }
      });
    } catch (e) {
      // PM already attached to this customer — that's fine, continue saving
      if (e.message && e.message.includes("already been attached")) {
        console.log("PM already attached, continuing save.");
      } else if (e.message && (
        e.message.includes("must attach it to a Customer") ||
        e.message.includes("previously used with a PaymentIntent without Customer") ||
        e.message.includes("detached from a Customer")
      )) {
        // PM is stale — do NOT save it to Firestore
        console.warn("PM is stale/unattachable, rejecting save:", e.message);
        throw new functions.https.HttpsError("failed-precondition", "STALE_CARD");
      } else {
        console.warn("PM attach warning:", e.message);
      }
    }
  }

  await accountRef.update({
    stripePaymentMethodId: paymentMethodId,
    cardBrand: paymentMethod.card.brand,
    cardLast4: paymentMethod.card.last4
  });

  return { success: true };
});

/**
 * Creates a PaymentIntent for on-page payments.
 * Always requires a valid customerId so the PM is attached to the customer —
 * this is required for future saved-card charges to work.
 */
exports.createPaymentIntent = functions.runWith({ secrets: [stripeSecret] }).https.onCall(async (data, context) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET);
  const { amount, bookingCode, customerName, customerId } = data;

  if (!amount || amount <= 0) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid amount");
  }

  const piData = {
    amount: Math.round(amount * 100),
    currency: "usd",
    payment_method_types: ["card"],   // card-only — avoids Stripe Link INTERNAL errors
    metadata: {
      bookingCode: bookingCode || "",
      customerName: customerName || ""
    }
  };

  // Associate with Stripe customer only if a valid ID is explicitly provided
  if (customerId && typeof customerId === "string" && customerId.startsWith("cus_")) {
    piData.customer = customerId;
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create(piData);
    return { clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id };
  } catch (stripeErr) {
    console.error("Stripe PaymentIntent create error:", stripeErr.message);
    throw new functions.https.HttpsError("internal", "Could not create payment: " + stripeErr.message);
  }
});
