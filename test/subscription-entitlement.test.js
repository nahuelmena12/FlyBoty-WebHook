import assert from "node:assert/strict";
import test from "node:test";

import {
  entitlementDecisionFromPayment,
  entitlementDecisionFromPreapproval,
  isVerifiedSubscriptionPayment,
  licenseStatusFromPayment,
  licenseStatusFromPreapproval,
  parseExternalReference,
} from "../index.js";

const SCHOOL_ID = "507f1f77bcf86cd799439011";
const ATTEMPT_ID = "0f8fad5b-d9cb-469f-a165-70867728950e";
const REFERENCE_A = "flyboty:v2:STANDARD:annual:5:1540000:"
  + ATTEMPT_ID + ":" + SCHOOL_ID;
const REFERENCE_B = "flyboty:v2:FULL:monthly:0:150000:"
  + "b3b2c1d0-e9f8-47a6-95b4-c3d2e1f0a9b8:" + SCHOOL_ID;
const REFERENCE_C = "flyboty:v2:LOW_COST:monthly:0:100000:"
  + "c3b2c1d0-e9f8-47a6-95b4-c3d2e1f0a9b8:" + SCHOOL_ID;
const V1_REFERENCE = "flyboty:STANDARD:annual:" + ATTEMPT_ID + ":" + SCHOOL_ID;
const LEGACY_REFERENCE = "STANDARD_" + SCHOOL_ID;
const CREATED_A = new Date("2026-08-01T08:00:00.000Z");
const CREATED_B = new Date("2026-08-02T08:00:00.000Z");
const CREATED_C = new Date("2026-08-03T08:00:00.000Z");

function v2Identity(reference, preapprovalId, attemptCreatedAt) {
  return {
    parsedReference: parseExternalReference(reference),
    preapprovalId,
    attemptCreatedAt,
  };
}

test("a preapproval authorization never grants a license", () => {
  assert.equal(licenseStatusFromPreapproval("inactive", "authorized"), "pending");
  assert.equal(licenseStatusFromPreapproval("pending", "authorized"), "pending");
  assert.equal(licenseStatusFromPreapproval("active", "authorized"), null);
});

test("cancelled, rejected, and pending payments fail closed", () => {
  assert.equal(licenseStatusFromPayment("inactive", "pending"), "pending");
  assert.equal(licenseStatusFromPayment("pending", "cancelled"), "inactive");
  assert.equal(licenseStatusFromPayment("pending", "rejected"), "inactive");
  assert.equal(licenseStatusFromPayment("active", "rejected"), "past_due");
});

test("only an approved payment activates the license", () => {
  assert.equal(licenseStatusFromPayment("inactive", "approved"), "active");
  assert.notEqual(licenseStatusFromPreapproval("inactive", "authorized"), "active");
});

test("accepts only FlyBoty checkout references", () => {
  assert.deepEqual(
    parseExternalReference(REFERENCE_A),
    {
      version: "v2",
      planId: "STANDARD",
      billingCycle: "annual",
      extraStudents: 5,
      amount: 1540000,
      attemptId: ATTEMPT_ID,
      schoolId: SCHOOL_ID,
      legacy: false,
    }
  );
  assert.equal(parseExternalReference("untrusted_" + SCHOOL_ID), null);
});

test("validates the approved payment against its preapproval and server reference", () => {
  const payment = {
    preapproval_id: "preapproval-a",
    external_reference: REFERENCE_A,
    transaction_amount: 1540000,
    currency_id: "ARS",
  };
  const subscription = {
    id: "preapproval-a",
    external_reference: REFERENCE_A,
    auto_recurring: {
      transaction_amount: 1540000,
      currency_id: "ARS",
    },
  };
  const parsed = parseExternalReference(REFERENCE_A);

  assert.equal(isVerifiedSubscriptionPayment(payment, subscription, parsed), true);
  assert.equal(
    isVerifiedSubscriptionPayment(
      { ...payment, transaction_amount: 1 },
      subscription,
      parsed
    ),
    false
  );
  assert.equal(
    isVerifiedSubscriptionPayment(
      { ...payment, preapproval_id: undefined },
      subscription,
      parsed,
      "preapproval-a"
    ),
    true
  );
  assert.equal(
    isVerifiedSubscriptionPayment(
      payment,
      subscription,
      parsed,
      "different-preapproval"
    ),
    false
  );
});

test("does not let a different checkout revoke or replace the active one", () => {
  const currentSchool = {
    subscriptionStatus: "active",
    mercadoPagoEntitlementExternalReference: REFERENCE_B,
    mercadoPagoEntitlementUpdatedAt: new Date("2026-08-01T10:00:00.000Z"),
    mercadoPagoSubscriptionExternalReference: REFERENCE_B,
    mercadoPagoSubscriptionLastEventAt: new Date("2026-08-01T10:00:00.000Z"),
  };
  const later = new Date("2026-08-02T10:00:00.000Z");

  assert.equal(
    entitlementDecisionFromPreapproval(currentSchool, REFERENCE_A, "canceled", later),
    null
  );
  assert.equal(
    entitlementDecisionFromPayment(
      currentSchool,
      REFERENCE_A,
      "rejected",
      later,
      { date_created: "2026-07-01T10:00:00.000Z" }
    ),
    null
  );
  assert.deepEqual(
    entitlementDecisionFromPreapproval(
      currentSchool,
      REFERENCE_B,
      "canceled",
      later
    ),
    { subscriptionStatus: "inactive" }
  );
});

test("a late event from A cannot revoke or activate pending attempt B", () => {
  const pendingB = {
    subscriptionStatus: "pending",
    mercadoPagoEntitlementExternalReference: REFERENCE_B,
    mercadoPagoEntitlementPreapprovalId: "preapproval-b",
    mercadoPagoEntitlementAttemptCreatedAt: CREATED_B,
    mercadoPagoEntitlementUpdatedAt: new Date("2026-08-02T09:00:00.000Z"),
  };
  const laterEvent = new Date("2026-08-04T12:00:00.000Z");

  assert.equal(
    entitlementDecisionFromPreapproval(
      pendingB,
      REFERENCE_A,
      "canceled",
      laterEvent,
      v2Identity(REFERENCE_A, "preapproval-a", CREATED_A)
    ),
    null
  );
  assert.equal(
    entitlementDecisionFromPayment(
      pendingB,
      REFERENCE_A,
      "approved",
      laterEvent,
      { id: "preapproval-a", date_created: CREATED_A },
      v2Identity(REFERENCE_A, "preapproval-a", CREATED_A)
    ),
    null
  );
  assert.deepEqual(
    entitlementDecisionFromPreapproval(
      pendingB,
      REFERENCE_B,
      "canceled",
      laterEvent,
      v2Identity(REFERENCE_B, "preapproval-b", CREATED_B)
    ),
    {
      subscriptionStatus: "inactive",
      preapprovalId: "preapproval-b",
      attemptCreatedAt: CREATED_B,
    }
  );
  assert.deepEqual(
    entitlementDecisionFromPayment(
      pendingB,
      REFERENCE_B,
      "approved",
      laterEvent,
      { id: "preapproval-b", date_created: CREATED_B },
      v2Identity(REFERENCE_B, "preapproval-b", CREATED_B)
    ),
    {
      subscriptionStatus: "active",
      preapprovalId: "preapproval-b",
      attemptCreatedAt: CREATED_B,
    }
  );
});

test("the provider event update time cannot make an older attempt replace a newer one", () => {
  const pendingB = {
    subscriptionStatus: "pending",
    mercadoPagoEntitlementExternalReference: REFERENCE_B,
    mercadoPagoEntitlementPreapprovalId: "preapproval-b",
    mercadoPagoEntitlementAttemptCreatedAt: CREATED_B,
    mercadoPagoEntitlementUpdatedAt: new Date("2026-08-02T09:00:00.000Z"),
  };
  const lateModifiedAt = new Date("2026-08-10T12:00:00.000Z");

  assert.equal(
    entitlementDecisionFromPreapproval(
      pendingB,
      REFERENCE_A,
      "authorized",
      lateModifiedAt,
      v2Identity(REFERENCE_A, "preapproval-a", CREATED_A)
    ),
    null
  );

  const inactiveB = { ...pendingB, subscriptionStatus: "inactive" };
  assert.deepEqual(
    entitlementDecisionFromPreapproval(
      inactiveB,
      REFERENCE_C,
      "authorized",
      new Date("2026-08-03T09:00:00.000Z"),
      v2Identity(REFERENCE_C, "preapproval-c", CREATED_C)
    ),
    {
      subscriptionStatus: "pending",
      preapprovalId: "preapproval-c",
      attemptCreatedAt: CREATED_C,
    }
  );
});

test("v1 and legacy references cannot grant an entitlement", () => {
  const inactiveSchool = { subscriptionStatus: "inactive" };
  const v1Subscription = {
    id: "preapproval-v1",
    external_reference: V1_REFERENCE,
    date_created: CREATED_A,
  };

  assert.equal(
    entitlementDecisionFromPreapproval(
      inactiveSchool,
      V1_REFERENCE,
      "authorized",
      CREATED_A,
      {
        parsedReference: parseExternalReference(V1_REFERENCE),
        preapprovalId: "preapproval-v1",
        attemptCreatedAt: CREATED_A,
      }
    ),
    null
  );
  assert.equal(
    entitlementDecisionFromPayment(
      inactiveSchool,
      V1_REFERENCE,
      "approved",
      CREATED_A,
      v1Subscription,
      {
        parsedReference: parseExternalReference(V1_REFERENCE),
        preapprovalId: "preapproval-v1",
        attemptCreatedAt: CREATED_A,
      }
    ),
    null
  );
});

test("a legacy or v1 loss needs an exact existing preapproval binding", () => {
  const legacySchool = {
    subscriptionStatus: "active",
    mercadoPagoActiveSubscriptionId: "legacy-bound",
  };
  const legacyIdentity = {
    parsedReference: parseExternalReference(LEGACY_REFERENCE),
    preapprovalId: "legacy-bound",
    attemptCreatedAt: CREATED_A,
  };

  assert.deepEqual(
    entitlementDecisionFromPreapproval(
      legacySchool,
      LEGACY_REFERENCE,
      "canceled",
      new Date("2026-08-04T12:00:00.000Z"),
      legacyIdentity
    ),
    { subscriptionStatus: "inactive", preapprovalId: "legacy-bound" }
  );
  assert.deepEqual(
    entitlementDecisionFromPayment(
      legacySchool,
      LEGACY_REFERENCE,
      "rejected",
      new Date("2026-08-04T12:00:00.000Z"),
      { id: "legacy-bound", date_created: CREATED_A },
      legacyIdentity
    ),
    { subscriptionStatus: "past_due", preapprovalId: "legacy-bound" }
  );
  assert.equal(
    entitlementDecisionFromPreapproval(
      legacySchool,
      LEGACY_REFERENCE,
      "canceled",
      new Date("2026-08-04T12:00:00.000Z"),
      { ...legacyIdentity, preapprovalId: "other-preapproval" }
    ),
    null
  );
});
