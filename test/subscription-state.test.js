import test from "node:test";
import assert from "node:assert/strict";

import {
  addCalendarMonths,
  entitlementRevocationFields,
  extractCheckoutDetails,
  hasPaidAccess,
  mapSubscriptionStatus,
  pauseTransitionFields,
  periodEndFromSubscription,
} from "../index.js";

test("authorized sin pago continúa pendiente", () => {
  assert.equal(mapSubscriptionStatus("authorized"), "pending");
  assert.equal(mapSubscriptionStatus("cancelled"), "cancelled");
  assert.equal(mapSubscriptionStatus("canceled"), "cancelled");
});

test("parsea referencias únicas y mantiene compatibilidad legacy", () => {
  const schoolId = "69ecd6c49d8e25a2ac2ab43e";
  assert.deepEqual(
    extractCheckoutDetails(
      `LOW_COST_ANNUAL_15_9f631176-51f2-41f0-a571-9fdbbde2ca51_${schoolId}`
    ),
    {
      schoolId,
      planId: "LOW_COST",
      billingCycle: "annual",
      extraStudents: 15,
      attemptId: "9f631176-51f2-41f0-a571-9fdbbde2ca51",
    }
  );
  assert.equal(
    extractCheckoutDetails(`STANDARD_${schoolId}`, "FlyBoty Standard · Mensual")
      .billingCycle,
    "monthly"
  );
});

test("suma meses calendario sin desbordar fin de mes", () => {
  assert.equal(
    addCalendarMonths(new Date("2028-01-31T12:00:00.000Z"), 1).toISOString(),
    "2028-02-29T12:00:00.000Z"
  );
});

test("la factura concede exactamente un ciclo y no confía en next_payment_date", () => {
  const start = new Date("2026-08-25T19:19:17.000Z");
  assert.equal(
    periodEndFromSubscription(
      {
        next_payment_date: "2026-09-25T18:32:20.000Z",
        auto_recurring: {
          frequency: 1,
          frequency_type: "months",
          end_date: "2030-01-01T00:00:00.000Z",
        },
      },
      start,
      "monthly"
    ).toISOString(),
    "2026-09-25T19:19:17.000Z"
  );
});

test("un next_payment_date pendiente sin pago no habilita acceso legacy", () => {
  assert.equal(
    hasPaidAccess(
      { subscriptionNextPaymentDate: new Date("2027-01-01T00:00:00.000Z") },
      new Date("2026-01-01T00:00:00.000Z")
    ),
    false
  );
});

test("sólo un reverso del pago que otorgó el período revoca acceso", () => {
  const school = {
    subscriptionLastSuccessfulPaymentId: "payment-1",
    subscriptionLastSuccessfulPaymentPreapprovalId: "preapproval-1",
    mercadoPagoSubscriptionId: "preapproval-1",
    mercadoPagoExternalReference: "STANDARD_school-1",
  };
  assert.equal(
    entitlementRevocationFields(school, {
      paymentId: "payment-2",
      status: "refunded",
    }),
    null
  );
  const revoked = entitlementRevocationFields(school, {
    paymentId: "payment-1",
    preapprovalId: "preapproval-1",
    externalReference: "STANDARD_school-1",
    status: "charged_back",
    eventAt: "2026-08-26T00:00:00.000Z",
  });
  assert.equal(revoked.subscriptionStatus, "cancelled");
  assert.equal(
    revoked.subscriptionCurrentPeriodEnd.toISOString(),
    "2026-08-26T00:00:00.000Z"
  );
});

test("pausar no programa cancelación y una reactivación nueva restaura renovación", () => {
  const periodEnd = new Date("2026-09-25T00:00:00.000Z");
  const school = {
    subscriptionCurrentPeriodEnd: periodEnd,
    subscriptionLastSuccessfulPaymentId: "payment-1",
    subscriptionLastSuccessfulPaymentPreapprovalId: "preapproval-1",
    mercadoPagoSubscriptionId: "preapproval-1",
    mercadoPagoSubscriptionStatus: "paused",
    mercadoPagoSubscriptionProviderModifiedAt: new Date(
      "2026-08-25T00:00:00.000Z"
    ),
    subscriptionPaused: true,
    subscriptionCancelAtPeriodEnd: false,
  };
  const paused = pauseTransitionFields(school, "paused", {
    paidAccess: true,
    eventDate: "2026-08-25T00:00:00.000Z",
  });
  assert.equal(paused.subscriptionStatus, "active");
  assert.equal(paused.subscriptionRenews, false);
  assert.equal(paused.subscriptionCancelAtPeriodEnd, undefined);

  assert.equal(
    pauseTransitionFields(school, "authorized", {
      paidAccess: true,
      eventDate: "2026-08-24T00:00:00.000Z",
    }),
    null
  );
  const reactivated = pauseTransitionFields(school, "authorized", {
    paidAccess: true,
    eventDate: "2026-08-26T00:00:00.000Z",
  });
  assert.equal(reactivated.subscriptionPaused, false);
  assert.equal(reactivated.subscriptionRenews, true);
  assert.equal(reactivated.subscriptionNextPaymentDate, periodEnd);
});
