import crypto from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";

const MERCADO_PAGO_API = "https://api.mercadopago.com";
const WEBHOOK_CLAIM_LEASE_MS = 10 * 60 * 1000;

let config;

const mongoState = {
  client: null,
  db: null,
  connecting: null,
  indexesReady: false,
};

function loadConfig(values = process.env) {
  return {
    nodeEnv: values.ENVIRONMENT || values.NODE_ENV || "development",
    gatewaySharedSecret: values.GATEWAY_SHARED_SECRET || "",
    trustProxy: parseProxyValue(values.TRUST_PROXY),
    requireHttps: parseBoolean(values.REQUIRE_HTTPS, false),
    maxBodySize: values.MAX_BODY_SIZE || "32kb",
    signatureMaxAgeSeconds: parseInteger(
      values.SIGNATURE_MAX_AGE_SECONDS,
      300
    ),
    webhookRateLimit: {
      windowMs: parseInteger(values.WEBHOOK_RATE_LIMIT_WINDOW_MS, 60000),
      max: parseInteger(values.WEBHOOK_RATE_LIMIT_MAX, 120),
    },
    healthRateLimit: {
      windowMs: parseInteger(values.HEALTH_RATE_LIMIT_WINDOW_MS, 60000),
      max: parseInteger(values.HEALTH_RATE_LIMIT_MAX, 30),
    },
    webhookEventRetentionDays: parseInteger(
      values.WEBHOOK_EVENT_RETENTION_DAYS,
      90
    ),
    logWebhookPayloads: parseBoolean(values.LOG_WEBHOOK_PAYLOADS, false),
    allowedWebhookIps: parseCsv(values.ALLOWED_WEBHOOK_IPS),
    mongodbUri: values.MONGODB_URI,
    mongodbDb: values.MONGODB_DB || "FlyBotyInstruccion",
    mpAccessToken: values.MP_ACCESS_TOKEN,
    mpWebhookSecret: values.MP_WEBHOOK_SECRET,
  };
}

function initialize(values) {
  if (config) return;
  const loadedConfig = loadConfig(values);
  validateConfig(loadedConfig);
  config = loadedConfig;
}

// El SDK oficial "mercadopago" depende de node-fetch internamente
// (response.headers.raw()), que no existe en el runtime de Cloudflare
// Workers. Se llama a la API REST directo con fetch nativo.
async function mercadoPagoGet(path) {
  const response = await fetch(`${MERCADO_PAGO_API}${path}`, {
    headers: { authorization: `Bearer ${config.mpAccessToken}` },
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(
      payload?.message || payload?.error || `Mercado Pago respondió ${response.status}`
    );
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function validateConfig(currentConfig) {
  if (!currentConfig.mpAccessToken) {
    throw new Error("Falta MP_ACCESS_TOKEN en el .env");
  }

  if (!currentConfig.mpWebhookSecret) {
    throw new Error("Falta MP_WEBHOOK_SECRET en el .env");
  }

  if (!currentConfig.mongodbUri) {
    throw new Error("Falta MONGODB_URI en el .env");
  }

  if (currentConfig.signatureMaxAgeSeconds < 30) {
    throw new Error("SIGNATURE_MAX_AGE_SECONDS debe ser al menos 30");
  }
}

function parseInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  return ["true", "1", "yes", "on"].includes(String(value).toLowerCase());
}

function parseCsv(value) {
  if (!value) return [];
  return String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseProxyValue(value) {
  if (value === undefined || value === null || value === "") return false;
  if (["true", "1"].includes(String(value).toLowerCase())) return true;
  if (["false", "0"].includes(String(value).toLowerCase())) return false;

  const numeric = Number.parseInt(value, 10);
  return Number.isFinite(numeric) ? numeric : value;
}

function sanitizeHeaders(headers) {
  const clone = { ...headers };

  for (const name of Object.keys(clone)) {
    if (["authorization", "cookie", "x-signature"].includes(name.toLowerCase())) {
      clone[name] = "[redacted]";
    }
  }

  return clone;
}

function logWebhookRequest(req) {
  console.log(`\n[webhook] Notificacion recibida (${req.requestId})`);
  console.log("[webhook] Headers:", JSON.stringify(sanitizeHeaders(req.headers), null, 2));

  if (config.logWebhookPayloads) {
    console.log("[webhook] Body:", JSON.stringify(req.body, null, 2));
  } else {
    console.log(
      "[webhook] Body resumido:",
      JSON.stringify(
        {
          id: req.body?.id || null,
          type: req.body?.type || null,
          action: req.body?.action || null,
          data: req.body?.data || null,
        },
        null,
        2
      )
    );
  }
}

async function getMongoDb() {
  if (mongoState.db) return mongoState.db;
  if (mongoState.connecting) return mongoState.connecting;

  mongoState.connecting = (async () => {
    const mongoClient = new MongoClient(config.mongodbUri, {
      maxPoolSize: 10,
      minPoolSize: 1,
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 15000,
    });

    await mongoClient.connect();
    mongoState.client = mongoClient;
    mongoState.db = mongoClient.db(config.mongodbDb);

    if (!mongoState.indexesReady) {
      const retentionSeconds = config.webhookEventRetentionDays * 24 * 60 * 60;

      await Promise.all([
        mongoState.db
          .collection("mercadopago_webhook_events")
          .createIndex({ eventKey: 1 }, { unique: true }),
        mongoState.db
          .collection("mercadopago_webhook_events")
          .createIndex({ receivedAt: -1 }),
        mongoState.db
          .collection("mercadopago_webhook_events")
          .createIndex(
            { createdAt: 1 },
            { expireAfterSeconds: retentionSeconds }
          ),
        mongoState.db
          .collection("schools")
          .createIndex({ mercadoPagoExternalReference: 1 }, { sparse: true }),
      ]);
      mongoState.indexesReady = true;
    }

    console.log(`[MongoDB] Webhook conectado a DB: ${config.mongodbDb}`);
    return mongoState.db;
  })();

  try {
    return await mongoState.connecting;
  } finally {
    mongoState.connecting = null;
  }
}

async function closeMongo() {
  if (mongoState.client) {
    await mongoState.client.close();
  }

  mongoState.client = null;
  mongoState.db = null;
  mongoState.connecting = null;
}

function getRequestIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return String(forwarded).split(",")[0].trim();
  }

  return req.ip || req.socket?.remoteAddress || "unknown";
}

function parseSignatureHeader(header) {
  if (!header) return {};

  return Object.fromEntries(
    String(header)
      .split(",")
      .map((part) => part.trim().split("="))
      .filter((entry) => entry.length === 2)
  );
}

function validateSignature(req) {
  const xSignature = req.headers["x-signature"];
  const xRequestId = req.headers["x-request-id"];
  const dataId = req.query["data.id"] || req.body?.data?.id;

  if (!xSignature) {
    return { valid: false, reason: "missing_signature" };
  }

  if (!xRequestId || !dataId) {
    return { valid: false, reason: "missing_request_fields" };
  }

  const parts = parseSignatureHeader(xSignature);
  const ts = parts.ts;
  const receivedHash = parts.v1;

  if (!ts || !receivedHash) {
    return { valid: false, reason: "malformed_signature" };
  }

  const timestampSeconds = Number.parseInt(ts, 10);
  if (!Number.isFinite(timestampSeconds)) {
    return { valid: false, reason: "invalid_timestamp" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampSeconds) > config.signatureMaxAgeSeconds) {
    return { valid: false, reason: "stale_signature" };
  }

  const manifest = `id:${dataId};request-id:${xRequestId};ts:${ts};`;
  const expectedHash = crypto
    .createHmac("sha256", config.mpWebhookSecret)
    .update(manifest)
    .digest("hex");

  if (expectedHash.length !== receivedHash.length) {
    return { valid: false, reason: "hash_length_mismatch" };
  }

  try {
    const matches = crypto.timingSafeEqual(
      Buffer.from(expectedHash, "utf8"),
      Buffer.from(receivedHash, "utf8")
    );

    return matches
      ? { valid: true, reason: "ok" }
      : { valid: false, reason: "hash_mismatch" };
  } catch {
    return { valid: false, reason: "compare_failed" };
  }
}

function buildEventContext(req) {
  const payloadType = req.body?.type || req.body?.action || "unknown";
  const resourceId = req.body?.data?.id || req.query["data.id"] || null;
  const notificationId = req.body?.id || null;
  const version =
    req.body?.version !== undefined && req.body?.version !== null
      ? String(req.body.version)
      : "na";

  return {
    payloadType,
    resourceId,
    notificationId,
    action: req.body?.action || null,
    version,
    receivedAt: new Date(),
    requestId: req.requestId,
    sourceIp: getRequestIp(req),
    eventKey: [
      payloadType,
      notificationId || "no-notification-id",
      resourceId || "no-resource-id",
      version,
    ].join(":"),
  };
}

const MAX_EXTRA_STUDENTS = 10000;
const BASE_STUDENTS = 50;
const CURRENT_V2_EXTERNAL_REFERENCE_PATTERN =
  /^flyboty:v2:(LOW_COST|STANDARD|FULL):(monthly|annual):(0|[1-9][0-9]{0,4}):([1-9][0-9]{0,8}):([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}):([a-f0-9]{24})$/i;
const CURRENT_V1_EXTERNAL_REFERENCE_PATTERN =
  /^flyboty:(LOW_COST|STANDARD|FULL):(monthly|annual):([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}):([a-f0-9]{24})$/i;
const LEGACY_EXTERNAL_REFERENCE_PATTERN =
  /^(LOW_COST|STANDARD|FULL)_([a-f0-9]{24})$/i;
const LICENSE_STATUSES = new Set([
  "active",
  "inactive",
  "pending",
  "trialing",
  "past_due",
]);

function parseExternalReference(externalReference) {
  if (!externalReference) return null;

  const ref = String(externalReference).trim();
  const currentV2 = ref.match(CURRENT_V2_EXTERNAL_REFERENCE_PATTERN);
  if (currentV2) {
    const extraStudents = Number(currentV2[3]);
    const amount = Number(currentV2[4]);
    if (!Number.isSafeInteger(extraStudents) || extraStudents > MAX_EXTRA_STUDENTS
      || !Number.isSafeInteger(amount) || amount <= 0) {
      return null;
    }
    return {
      version: "v2",
      planId: currentV2[1].toUpperCase(),
      billingCycle: currentV2[2].toLowerCase(),
      extraStudents,
      amount,
      attemptId: currentV2[5].toLowerCase(),
      schoolId: currentV2[6].toLowerCase(),
      legacy: false,
    };
  }

  const currentV1 = ref.match(CURRENT_V1_EXTERNAL_REFERENCE_PATTERN);
  if (currentV1) {
    return {
      version: "v1",
      planId: currentV1[1].toUpperCase(),
      billingCycle: currentV1[2].toLowerCase(),
      extraStudents: null,
      amount: null,
      attemptId: currentV1[3].toLowerCase(),
      schoolId: currentV1[4].toLowerCase(),
      legacy: false,
    };
  }

  const legacy = ref.match(LEGACY_EXTERNAL_REFERENCE_PATTERN);
  if (legacy && ObjectId.isValid(legacy[2])) {
    return {
      version: "legacy",
      planId: legacy[1].toUpperCase(),
      billingCycle: null,
      extraStudents: null,
      amount: null,
      attemptId: null,
      schoolId: legacy[2].toLowerCase(),
      legacy: true,
    };
  }

  return null;
}

function extractSchoolIdFromExternalReference(externalReference) {
  return parseExternalReference(externalReference)?.schoolId || null;
}

// Extrae el planId del external_reference con formato "PLAN_ID_<24hexSchoolId>"
function extractPlanIdFromExternalReference(externalReference) {
  return parseExternalReference(externalReference)?.planId || null;
}

// Deriva billingCycle del campo reason (ej: "FlyBoty LOW_COST · Anual")
function extractBillingCycleFromReason(reason) {
  if (!reason) return null;
  const r = String(reason).toLowerCase();
  if (r.includes("anual")) return "annual";
  if (r.includes("mensual")) return "monthly";
  return null;
}

function extractBillingCycle(externalReference, reason) {
  const parsed = parseExternalReference(externalReference);
  if (parsed?.billingCycle) return parsed.billingCycle;
  return extractBillingCycleFromReason(reason);
}

function normalizeLicenseStatus(value) {
  return LICENSE_STATUSES.has(value) ? value : "inactive";
}

// A preapproval only represents the payer's authorization. It must never
// activate the product; only a verified payment can grant access.
function licenseStatusFromPreapproval(currentStatus, preapprovalStatus) {
  const current = normalizeLicenseStatus(currentStatus);
  if (preapprovalStatus === "pending" || preapprovalStatus === "authorized") {
    return current === "active" ? null : "pending";
  }
  if (preapprovalStatus === "paused"
    || preapprovalStatus === "canceled"
    || preapprovalStatus === "cancelled") {
    return "inactive";
  }
  return null;
}

function licenseStatusFromPayment(currentStatus, paymentStatus) {
  const current = normalizeLicenseStatus(currentStatus);
  if (paymentStatus === "approved") return "active";
  if (paymentStatus === "pending" || paymentStatus === "in_process") {
    return current === "active" || current === "past_due" ? null : "pending";
  }
  if (["cancelled", "canceled", "rejected", "refunded", "charged_back"].includes(paymentStatus)) {
    return current === "active" ? "past_due" : "inactive";
  }
  return null;
}

function asValidDate(value) {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function resourceDate(result, fallback = new Date()) {
  const source = result?.date_last_updated
    || result?.last_modified
    || result?.date_approved
    || result?.date_created;
  return asValidDate(source) || fallback;
}

function resourceCreatedAt(result) {
  return asValidDate(result?.date_created);
}

function sameExternalReference(left, right) {
  return Boolean(left) && Boolean(right) && String(left) === String(right);
}

function providerId(value) {
  return value === undefined || value === null || value === "" ? null : String(value);
}

function isV2Reference(parsedReference) {
  return parsedReference?.version === "v2";
}

function isPreapprovalLossStatus(status) {
  return status === "paused" || status === "canceled" || status === "cancelled";
}

function isPaymentLossStatus(status) {
  return ["cancelled", "canceled", "rejected", "refunded", "charged_back"].includes(status);
}

function sameEntitlementIdentity(school, externalReference, preapprovalId) {
  if (!sameExternalReference(
    school?.mercadoPagoEntitlementExternalReference,
    externalReference
  )) {
    return false;
  }

  const currentPreapprovalId = providerId(
    school?.mercadoPagoEntitlementPreapprovalId
  );
  const incomingPreapprovalId = providerId(preapprovalId);

  // Old v2 records may not yet have the binding field. In that case the
  // unique v2 reference remains the compatibility identity until its next
  // verified event backfills the preapproval id.
  return !currentPreapprovalId
    || !incomingPreapprovalId
    || currentPreapprovalId === incomingPreapprovalId;
}

function hasExactLegacyEntitlementBinding(school, preapprovalId) {
  const incomingPreapprovalId = providerId(preapprovalId);
  if (!incomingPreapprovalId) return false;

  // `mercadoPagoActiveSubscriptionId` and `mercadoPagoSubscriptionId` are
  // historical fields. They are accepted only as an exact id match so legacy
  // references, which were reused per school/plan, can never select a newer
  // subscription merely by sharing an external_reference.
  const currentPreapprovalId = providerId(
    school?.mercadoPagoEntitlementPreapprovalId
  ) || providerId(school?.mercadoPagoActiveSubscriptionId)
    || providerId(school?.mercadoPagoSubscriptionId);

  return Boolean(currentPreapprovalId
    && currentPreapprovalId === incomingPreapprovalId);
}

function incomingAttemptIsNewer(school, externalReference, preapprovalId, attemptCreatedAt) {
  const currentReference = school?.mercadoPagoEntitlementExternalReference;
  if (!currentReference || sameEntitlementIdentity(school, externalReference, preapprovalId)) {
    return true;
  }

  const incomingCreatedAt = asValidDate(attemptCreatedAt);
  if (!incomingCreatedAt) return false;

  const currentCreatedAt = asValidDate(
    school?.mercadoPagoEntitlementAttemptCreatedAt
  );
  // A pre-existing entitlement without the new creation timestamp is a
  // migration case. Accept a real, dated v2 attempt once, then persist its
  // identity so all later ordering is deterministic.
  if (!currentCreatedAt) return true;
  return incomingCreatedAt.getTime() > currentCreatedAt.getTime();
}

function entitlementDecision(subscriptionStatus, preapprovalId, attemptCreatedAt) {
  return {
    subscriptionStatus,
    ...(preapprovalId ? { preapprovalId } : {}),
    ...(attemptCreatedAt ? { attemptCreatedAt } : {}),
  };
}

function paymentPreapprovalId(payment) {
  const value = payment?.preapproval_id || payment?.metadata?.preapproval_id;
  return value === undefined || value === null || value === "" ? null : String(value);
}

function amountsMatch(left, right) {
  const leftAmount = Number(left);
  const rightAmount = Number(right);
  return Number.isFinite(leftAmount)
    && Number.isFinite(rightAmount)
    && Math.abs(leftAmount - rightAmount) < 0.01;
}

function isVerifiedSubscriptionPayment(
  payment,
  subscription,
  parsedReference,
  preapprovalIdOverride = null
) {
  const paymentPreapproval = paymentPreapprovalId(payment);
  const fallbackPreapproval = providerId(preapprovalIdOverride);
  // When both authenticated Mercado Pago resources identify a subscription,
  // disagreement is unsafe: keep the payment as audit-only.
  if (paymentPreapproval && fallbackPreapproval
    && paymentPreapproval !== fallbackPreapproval) {
    return false;
  }
  const preapprovalId = paymentPreapproval || fallbackPreapproval;
  if (!preapprovalId || !subscription || String(subscription.id) !== preapprovalId) {
    return false;
  }

  const paymentReference = payment?.external_reference;
  if (!sameExternalReference(paymentReference, subscription?.external_reference)) {
    return false;
  }

  if (parsedReference?.amount !== null && parsedReference?.amount !== undefined) {
    if (String(payment?.currency_id || "").toUpperCase() !== "ARS"
      || String(subscription?.auto_recurring?.currency_id || "").toUpperCase() !== "ARS"
      || !amountsMatch(payment?.transaction_amount, parsedReference.amount)
      || !amountsMatch(subscription?.auto_recurring?.transaction_amount, parsedReference.amount)) {
      return false;
    }
  }

  return true;
}

function entitlementDecisionFromPreapproval(
  school,
  externalReference,
  preapprovalStatus,
  eventAt,
  identity = {}
) {
  const entitlementStatus = licenseStatusFromPreapproval(
    school?.subscriptionStatus,
    preapprovalStatus
  );
  if (!entitlementStatus) return null;

  const parsedReference = identity.parsedReference || parseExternalReference(externalReference);
  const preapprovalId = providerId(identity.preapprovalId);
  const attemptCreatedAt = asValidDate(identity.attemptCreatedAt);
  const currentStatus = normalizeLicenseStatus(school?.subscriptionStatus);
  const currentReference = school?.mercadoPagoEntitlementExternalReference;
  const sameReference = sameExternalReference(currentReference, externalReference);
  const sameEntitlement = sameEntitlementIdentity(
    school,
    externalReference,
    preapprovalId
  );
  const currentEntitlementAt = asValidDate(school?.mercadoPagoEntitlementUpdatedAt);

  if (!isV2Reference(parsedReference)) {
    if (!isPreapprovalLossStatus(preapprovalStatus)
      || !hasExactLegacyEntitlementBinding(school, preapprovalId)
      || (currentReference && !sameReference)) {
      return null;
    }
    if (sameReference && currentEntitlementAt
      && currentEntitlementAt.getTime() > eventAt.getTime()) return null;
    return entitlementDecision(entitlementStatus, preapprovalId);
  }

  if (sameReference && !sameEntitlement) return null;
  if (sameEntitlement && currentEntitlementAt
    && currentEntitlementAt.getTime() > eventAt.getTime()) return null;

  if (preapprovalStatus === "pending" || preapprovalStatus === "authorized") {
    if (currentStatus === "active" || currentStatus === "past_due") {
      return null;
    }
    if (!sameEntitlement && (!attemptCreatedAt || !incomingAttemptIsNewer(
      school,
      externalReference,
      preapprovalId,
      attemptCreatedAt
    ))) {
      return null;
    }
    return entitlementDecision("pending", preapprovalId, attemptCreatedAt);
  }

  // A cancellation must never create or take over an entitlement. It may
  // only revoke the exact v2 attempt currently bound to the school.
  if (!sameEntitlement) return null;
  return entitlementDecision("inactive", preapprovalId, attemptCreatedAt);
}

function entitlementDecisionFromPayment(
  school,
  externalReference,
  paymentStatus,
  paymentEventAt,
  verifiedSubscription,
  identity = {}
) {
  const entitlementStatus = licenseStatusFromPayment(
    school?.subscriptionStatus,
    paymentStatus
  );
  if (!entitlementStatus) return null;

  const parsedReference = identity.parsedReference || parseExternalReference(externalReference);
  const preapprovalId = providerId(identity.preapprovalId)
    || providerId(verifiedSubscription?.id);
  const attemptCreatedAt = asValidDate(identity.attemptCreatedAt)
    || resourceCreatedAt(verifiedSubscription);
  const currentReference = school?.mercadoPagoEntitlementExternalReference;
  const sameReference = sameExternalReference(currentReference, externalReference);
  const sameEntitlement = sameEntitlementIdentity(
    school,
    externalReference,
    preapprovalId
  );
  const currentEntitlementAt = asValidDate(school?.mercadoPagoEntitlementUpdatedAt);

  if (!isV2Reference(parsedReference)) {
    if (!isPaymentLossStatus(paymentStatus)
      || !hasExactLegacyEntitlementBinding(school, preapprovalId)
      || (currentReference && !sameReference)) {
      return null;
    }
    if (sameReference && currentEntitlementAt
      && currentEntitlementAt.getTime() > paymentEventAt.getTime()) return null;
    return entitlementDecision(entitlementStatus, preapprovalId);
  }

  if (sameReference && !sameEntitlement) return null;
  if (sameEntitlement && currentEntitlementAt
    && currentEntitlementAt.getTime() > paymentEventAt.getTime()) return null;

  if (sameEntitlement) {
    return entitlementDecision(entitlementStatus, preapprovalId, attemptCreatedAt);
  }

  // A different attempt may replace the current entitlement only after a
  // verified approved charge, and only when the subscription itself was
  // created later. Provider event timestamps are not a checkout ordering key.
  if (currentReference && entitlementStatus !== "active") return null;
  if (!attemptCreatedAt || !incomingAttemptIsNewer(
    school,
    externalReference,
    preapprovalId,
    attemptCreatedAt
  )) {
    return null;
  }

  return entitlementDecision(entitlementStatus, preapprovalId, attemptCreatedAt);
}

function maskEmail(value) {
  const email = typeof value === "string" ? value.trim() : "";
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(0, 1) + "***@" + email.slice(at + 1);
}

function buildSchoolEventEntry({
  eventKey,
  sourceType,
  sourceId,
  action,
  status,
  amount,
  externalReference,
  receivedAt,
  rawEventId,
}) {
  return {
    eventKey,
    sourceType,
    sourceId: sourceId || null,
    action: action || null,
    status: status || null,
    amount: amount ?? null,
    externalReference: externalReference || null,
    rawEventId: rawEventId || null,
    receivedAt,
  };
}

async function registerWebhookEvent({
  context,
  req,
  signatureResult,
  processingState,
  notes,
}) {
  const db = await getMongoDb();
  const collection = db.collection("mercadopago_webhook_events");
  const eventKey = signatureResult.valid
    ? context.eventKey
    : context.eventKey + ":invalid:" + context.requestId;

  const result = await collection.updateOne(
    { eventKey },
    {
      $setOnInsert: {
        eventKey,
        payloadType: context.payloadType,
        action: context.action,
        notificationId: context.notificationId,
        resourceId: context.resourceId,
        version: context.version,
        signatureValid: signatureResult.valid,
        signatureReason: signatureResult.reason,
        headers: sanitizeHeaders(req.headers),
        body: req.body,
        query: req.query,
        requestId: context.requestId,
        sourceIp: context.sourceIp,
        receivedAt: context.receivedAt,
        processingState,
        notes: notes || null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      $set: {
        lastReceivedAt: new Date(),
      },
      $inc: {
        receiveCount: 1,
      },
    },
    { upsert: true }
  );

  return {
    inserted: result.upsertedCount === 1,
  };
}

async function claimWebhookEvent({ context, req, signatureResult }) {
  const db = await getMongoDb();
  const collection = db.collection("mercadopago_webhook_events");
  const now = new Date();
  const claimToken = crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + WEBHOOK_CLAIM_LEASE_MS);

  try {
    await collection.insertOne({
      eventKey: context.eventKey,
      payloadType: context.payloadType,
      action: context.action,
      notificationId: context.notificationId,
      resourceId: context.resourceId,
      version: context.version,
      signatureValid: signatureResult.valid,
      signatureReason: signatureResult.reason,
      headers: sanitizeHeaders(req.headers),
      body: req.body,
      query: req.query,
      requestId: context.requestId,
      sourceIp: context.sourceIp,
      receivedAt: context.receivedAt,
      lastReceivedAt: now,
      processingState: "processing",
      processingStartedAt: now,
      processingClaimToken: claimToken,
      processingLeaseExpiresAt: leaseExpiresAt,
      processingAttempts: 1,
      receiveCount: 1,
      notes: null,
      createdAt: now,
      updatedAt: now,
    });
    return { state: "claimed", claimToken };
  } catch (error) {
    if (error?.code !== 11000) throw error;
  }

  // Retry failed processing and recover an abandoned lease, but never run a
  // successfully completed event twice.
  const retryBefore = new Date(now.getTime() - WEBHOOK_CLAIM_LEASE_MS);
  const retry = await collection.updateOne(
    {
      eventKey: context.eventKey,
      $or: [
        { processingState: "processing_error" },
        { processingState: "received" },
        {
          processingState: "processing",
          $or: [
            { processingLeaseExpiresAt: { $lt: now } },
            {
              processingLeaseExpiresAt: { $exists: false },
              processingStartedAt: { $lt: retryBefore },
            },
          ],
        },
      ],
    },
    {
      $set: {
        processingState: "processing",
        processingStartedAt: now,
        processingClaimToken: claimToken,
        processingLeaseExpiresAt: leaseExpiresAt,
        lastReceivedAt: now,
        notes: null,
        updatedAt: now,
      },
      $inc: {
        receiveCount: 1,
        processingAttempts: 1,
      },
    }
  );

  if (retry.matchedCount === 1) {
    return { state: "claimed", claimToken };
  }

  const existing = await collection.findOne(
    { eventKey: context.eventKey },
    { projection: { processingState: 1 } }
  );
  return {
    state: existing?.processingState === "processed" ? "processed" : "in_progress",
    claimToken: null,
  };
}

async function finalizeWebhookEvent({
  context,
  claimToken,
  processingState,
  notes,
  resolvedSchoolId,
}) {
  const db = await getMongoDb();

  const result = await db.collection("mercadopago_webhook_events").updateOne(
    {
      eventKey: context.eventKey,
      processingState: "processing",
      processingClaimToken: claimToken,
    },
    {
      $set: {
        processingState,
        notes: notes || null,
        resolvedSchoolId: resolvedSchoolId || null,
        processedAt: new Date(),
        processingLeaseExpiresAt: null,
        updatedAt: new Date(),
      },
    }
  );

  return result.matchedCount === 1;
}

async function findSchoolByExternalReference(externalReference) {
  const schoolId = extractSchoolIdFromExternalReference(externalReference);
  if (!schoolId) return null;

  const db = await getMongoDb();
  const school = await db.collection("schools").findOne({
    _id: new ObjectId(schoolId),
  });

  if (!school) return null;

  return { schoolId, school };
}

function exactFieldCondition(field, value) {
  return value === undefined
    ? { [field]: { $exists: false } }
    : { [field]: value };
}

async function appendSchoolEventOnce(db, schoolId, entry) {
  await db.collection("schools").updateOne(
    {
      _id: schoolId,
      "mercadoPagoEventHistory.eventKey": { $ne: entry.eventKey },
    },
    {
      $push: {
        mercadoPagoEventHistory: {
          $each: [entry],
          $slice: -30,
        },
      },
    }
  );
}

async function updateCurrentSubscriptionMetadata({
  db,
  schoolId,
  subscriptionId,
  result,
  context,
  externalReference,
  eventAt,
  attemptCreatedAt,
}) {
  const subscriptionAttemptCreatedAt = asValidDate(attemptCreatedAt)
    || resourceCreatedAt(result);
  const nextPaymentDate = asValidDate(result?.next_payment_date);
  const payerEmailMasked = maskEmail(result?.payer_email);
  const metadata = {
    mercadoPagoExternalReference: externalReference,
    ...(payerEmailMasked ? { mercadoPagoPayerEmailMasked: payerEmailMasked } : {}),
    mercadoPagoLastWebhookAt: new Date(),
    mercadoPagoLastEventType: context.payloadType,
    mercadoPagoLastEventAction: context.action,
    mercadoPagoSubscriptionId: String(subscriptionId),
    mercadoPagoSubscriptionExternalReference: externalReference,
    mercadoPagoSubscriptionStatus: result?.status || null,
    mercadoPagoSubscriptionReason: result?.reason || null,
    mercadoPagoSubscriptionVersion: context.version,
    mercadoPagoSubscriptionLastEventAt: eventAt,
    ...(subscriptionAttemptCreatedAt
      ? { mercadoPagoSubscriptionAttemptCreatedAt: subscriptionAttemptCreatedAt }
      : {}),
    ...(nextPaymentDate ? { mercadoPagoSubscriptionNextPaymentDate: nextPaymentDate } : {}),
    updatedAt: new Date(),
  };

  const sameReferenceAndNotOlder = {
    $and: [
      { mercadoPagoSubscriptionExternalReference: externalReference },
      {
        $or: [
          { mercadoPagoSubscriptionLastEventAt: { $exists: false } },
          { mercadoPagoSubscriptionLastEventAt: null },
          { mercadoPagoSubscriptionLastEventAt: { $lte: eventAt } },
        ],
      },
    ],
  };
  const metadataOrdering = [sameReferenceAndNotOlder];
  if (subscriptionAttemptCreatedAt) {
    // `last_modified` orders state changes inside one subscription, but it
    // cannot order checkout attempts: an old subscription can be cancelled
    // long after a newer one was created. A different reference therefore
    // needs a strictly later `date_created`. If the old metadata predates
    // this field, leave it untouched until a same-reference event backfills
    // the creation date instead of guessing from a modification timestamp.
    metadataOrdering.push({
      $and: [
        { mercadoPagoSubscriptionExternalReference: { $ne: externalReference } },
        {
          $or: [
            { mercadoPagoSubscriptionExternalReference: { $exists: false } },
            { mercadoPagoSubscriptionExternalReference: null },
            {
              mercadoPagoSubscriptionAttemptCreatedAt: {
                $type: "date",
                $lt: subscriptionAttemptCreatedAt,
              },
            },
          ],
        },
      ],
    });
  }

  return db.collection("schools").updateOne(
    {
      _id: schoolId,
      $or: metadataOrdering,
    },
    { $set: metadata }
  );
}

async function applySchoolEntitlement({
  db,
  schoolId,
  decide,
  buildUpdate,
}) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const school = await db.collection("schools").findOne({ _id: schoolId });
    if (!school) return { applied: false, reason: "school_not_found" };

    const decision = decide(school);
    if (!decision) return { applied: false, reason: "not_current" };

    const result = await db.collection("schools").updateOne(
      {
        _id: schoolId,
        $and: [
          exactFieldCondition("subscriptionStatus", school.subscriptionStatus),
          exactFieldCondition(
            "mercadoPagoEntitlementExternalReference",
            school.mercadoPagoEntitlementExternalReference
          ),
          exactFieldCondition(
            "mercadoPagoEntitlementUpdatedAt",
            school.mercadoPagoEntitlementUpdatedAt
          ),
          exactFieldCondition(
            "mercadoPagoEntitlementPreapprovalId",
            school.mercadoPagoEntitlementPreapprovalId
          ),
          exactFieldCondition(
            "mercadoPagoEntitlementAttemptCreatedAt",
            school.mercadoPagoEntitlementAttemptCreatedAt
          ),
          exactFieldCondition(
            "mercadoPagoSubscriptionExternalReference",
            school.mercadoPagoSubscriptionExternalReference
          ),
          exactFieldCondition(
            "mercadoPagoSubscriptionLastEventAt",
            school.mercadoPagoSubscriptionLastEventAt
          ),
          exactFieldCondition(
            "mercadoPagoSubscriptionAttemptCreatedAt",
            school.mercadoPagoSubscriptionAttemptCreatedAt
          ),
        ],
      },
      { $set: buildUpdate(school, decision) }
    );

    if (result.matchedCount === 1) {
      return { applied: true, decision };
    }
  }

  throw new Error("No se pudo aplicar el estado de licencia de forma consistente");
}

async function updateSchoolFromSubscription({
  subscriptionId,
  result,
  context,
}) {
  const externalReference = result?.external_reference || null;
  const resolved = await findSchoolByExternalReference(externalReference);

  if (!resolved) {
    console.warn(
      `[suscripcion] No se encontro escuela para external_reference: ${externalReference}`
    );
    return null;
  }

  const eventDate = resourceDate(result);
  const parsedReference = parseExternalReference(externalReference);
  const attemptCreatedAt = resourceCreatedAt(result);
  const db = await getMongoDb();

  // Legacy and v1 references are deliberately audit-only unless an exact
  // preapproval binding authorizes a loss transition below. Do not let their
  // shared/stale references overwrite the current subscription metadata.
  if (isV2Reference(parsedReference)) {
    await updateCurrentSubscriptionMetadata({
      db,
      schoolId: resolved.school._id,
      subscriptionId,
      result,
      context,
      externalReference,
      eventAt: eventDate,
      attemptCreatedAt,
    });
  }

  await applySchoolEntitlement({
    db,
    schoolId: resolved.school._id,
    decide: (school) => entitlementDecisionFromPreapproval(
      school,
      externalReference,
      result?.status,
      eventDate,
      {
        parsedReference,
        preapprovalId: subscriptionId,
        attemptCreatedAt,
      }
    ),
    buildUpdate: (_school, decision) => ({
      subscriptionStatus: decision.subscriptionStatus,
      mercadoPagoEntitlementUpdatedAt: eventDate,
      mercadoPagoEntitlementExternalReference: externalReference,
      ...(decision.preapprovalId
        ? { mercadoPagoEntitlementPreapprovalId: decision.preapprovalId }
        : {}),
      ...(decision.attemptCreatedAt
        ? { mercadoPagoEntitlementAttemptCreatedAt: decision.attemptCreatedAt }
        : {}),
      mercadoPagoEntitlementSource: "subscription_preapproval",
      mercadoPagoEntitlementPreapprovalStatus: result?.status || null,
      updatedAt: new Date(),
    }),
  });

  await appendSchoolEventOnce(
    db,
    resolved.school._id,
    buildSchoolEventEntry({
      eventKey: context.eventKey,
      sourceType: context.payloadType,
      sourceId: subscriptionId,
      action: context.action,
      status: result?.status,
      externalReference,
      receivedAt: eventDate,
      rawEventId: context.notificationId,
    })
  );

  return resolved.schoolId;
}

async function updateSchoolFromPayment({
  paymentId,
  result,
  context,
  verifiedSubscription,
  preapprovalIdOverride = null,
}) {
  const externalReference = result?.external_reference || null;
  const resolved = await findSchoolByExternalReference(externalReference);

  if (!resolved) {
    console.warn(
      `[payment] No se encontro escuela para external_reference: ${externalReference}`
    );
    return null;
  }

  const receivedAt = new Date();
  const parsedReference = parseExternalReference(externalReference);
  const paymentPreapproval = paymentPreapprovalId(result);
  const fallbackPreapproval = providerId(preapprovalIdOverride);
  const preapprovalId = paymentPreapproval || fallbackPreapproval;
  const isVerified = isVerifiedSubscriptionPayment(
    result,
    verifiedSubscription,
    parsedReference,
    fallbackPreapproval
  );
  const approvedDate = asValidDate(result?.date_approved) || receivedAt;
  const paymentEventAt = resourceDate(result, receivedAt);
  const parsedPlanId = parsedReference?.planId || null;
  const parsedBillingCycle = parsedReference?.billingCycle
    || extractBillingCycle(externalReference, result?.description || result?.reason);

  const update = {
    mercadoPagoSchoolId: resolved.schoolId,
    mercadoPagoLastWebhookAt: receivedAt,
    mercadoPagoLastEventType: context.payloadType,
    mercadoPagoLastEventAction: context.action,
    mercadoPagoLastPaymentId: String(paymentId),
    mercadoPagoLastPaymentExternalReference: externalReference,
    mercadoPagoLastPaymentStatus: result?.status || null,
    mercadoPagoLastPaymentStatusDetail: result?.status_detail || null,
    mercadoPagoLastPaymentAmount: result?.transaction_amount ?? null,
    mercadoPagoLastPaymentCurrency: result?.currency_id || null,
    mercadoPagoLastPaymentDateCreated: result?.date_created
      ? new Date(result.date_created)
      : null,
    mercadoPagoLastPaymentDateApproved: result?.date_approved
      ? new Date(result.date_approved)
      : null,
    updatedAt: new Date(),
  };

  const db = await getMongoDb();

  await db.collection("schools").updateOne(
    { _id: resolved.school._id },
    { $set: update }
  );

  if (!isVerified) {
    console.warn("[payment] Pago sin preaprobacion verificada; solo se guarda auditoria:", paymentId);
  } else {
    const nextPaymentDate = asValidDate(verifiedSubscription?.next_payment_date);
    const entitlement = await applySchoolEntitlement({
      db,
      schoolId: resolved.school._id,
      decide: (school) => entitlementDecisionFromPayment(
        school,
        externalReference,
        result?.status,
        paymentEventAt,
        verifiedSubscription,
        {
          parsedReference,
          preapprovalId,
          attemptCreatedAt: resourceCreatedAt(verifiedSubscription),
        }
      ),
      buildUpdate: (_school, decision) => {
        const entitlementUpdate = {
          subscriptionStatus: decision.subscriptionStatus,
          mercadoPagoEntitlementUpdatedAt: paymentEventAt,
          mercadoPagoEntitlementExternalReference: externalReference,
          ...(decision.preapprovalId
            ? { mercadoPagoEntitlementPreapprovalId: decision.preapprovalId }
            : {}),
          ...(decision.attemptCreatedAt
            ? { mercadoPagoEntitlementAttemptCreatedAt: decision.attemptCreatedAt }
            : {}),
          mercadoPagoEntitlementPaymentId: String(paymentId),
          mercadoPagoEntitlementPaymentStatus: result?.status || null,
          mercadoPagoEntitlementSource: "payment",
          updatedAt: new Date(),
        };

        if (result?.status === "approved" && isV2Reference(parsedReference)) {
          if (parsedPlanId) entitlementUpdate.planName = parsedPlanId;
          if (parsedBillingCycle) entitlementUpdate.billingCycle = parsedBillingCycle;
          if (parsedReference?.extraStudents !== null
            && parsedReference?.extraStudents !== undefined) {
            entitlementUpdate.extraStudents = parsedReference.extraStudents;
            entitlementUpdate.maxStudents = BASE_STUDENTS + parsedReference.extraStudents;
          }
          if (preapprovalId) entitlementUpdate.mercadoPagoActiveSubscriptionId = preapprovalId;
          if (nextPaymentDate) entitlementUpdate.subscriptionNextPaymentDate = nextPaymentDate;
          entitlementUpdate.LastAprovedPaymentDate = approvedDate;
          entitlementUpdate.LastAprovedAmount = result?.transaction_amount ?? null;
        }

        return entitlementUpdate;
      },
    });

    if (!entitlement.applied) {
      console.log("[payment] Estado de licencia ignorado por evento no vigente:", paymentId);
    }
  }

  await appendSchoolEventOnce(
    db,
    resolved.school._id,
    buildSchoolEventEntry({
      eventKey: context.eventKey,
      sourceType: context.payloadType,
      sourceId: String(paymentId),
      action: context.action,
      status: result?.status,
      amount: result?.transaction_amount,
      externalReference,
      receivedAt: paymentEventAt,
      rawEventId: context.notificationId,
    })
  );

  return resolved.schoolId;
}

async function updateSchoolFromAuthorizedPayment({
  authorizedPaymentId,
  result,
  context,
  appendHistory = true,
}) {
  const externalReference =
    result?.external_reference ||
    result?.metadata?.external_reference ||
    result?.reason;
  const resolved = await findSchoolByExternalReference(externalReference);

  if (!resolved) {
    console.warn(
      `[authorized_payment] No se encontro escuela para external_reference: ${externalReference}`
    );
    return null;
  }

  const receivedAt = new Date();
  const db = await getMongoDb();

  await db.collection("schools").updateOne(
    { _id: resolved.school._id },
    {
      $set: {
        mercadoPagoSchoolId: resolved.schoolId,
        mercadoPagoLastWebhookAt: receivedAt,
        mercadoPagoLastEventType: context.payloadType,
        mercadoPagoLastEventAction: context.action,
        mercadoPagoLastAuthorizedPaymentId: String(authorizedPaymentId),
        mercadoPagoLastAuthorizedPaymentStatus:
          result?.status || result?.status_detail || "received",
        mercadoPagoLastAuthorizedPaymentDate: result?.date_created
          ? new Date(result.date_created)
          : receivedAt,
        updatedAt: new Date(),
      },
    }
  );

  if (appendHistory) {
    await appendSchoolEventOnce(
      db,
      resolved.school._id,
      buildSchoolEventEntry({
        eventKey: context.eventKey,
        sourceType: context.payloadType,
        sourceId: String(authorizedPaymentId),
        action: context.action,
        status: result?.status || result?.status_detail || "received",
        externalReference,
        receivedAt,
        rawEventId: context.notificationId,
      })
    );
  }

  return resolved.schoolId;
}

async function handlePaymentEvent(id, context, preapprovalIdOverride = null) {
  const result = await mercadoPagoGet(`/v1/payments/${id}`);
  const {
    status,
    status_detail: statusDetail,
    external_reference: externalReference,
    transaction_amount: transactionAmount,
    payer,
  } = result;

  console.log("[payment] ID:", id);
  console.log("[payment] Estado:", status, "-", statusDetail);
  console.log("[payment] Referencia:", externalReference);
  console.log("[payment] Monto:", transactionAmount);
  console.log("[payment] Pagador:", maskEmail(payer?.email));

  if (status === "approved") {
    console.log(`[payment] APROBADO - ref: ${externalReference}`);
  } else if (status === "rejected") {
    console.log(`[payment] RECHAZADO (${statusDetail}) - ref: ${externalReference}`);
  } else if (status === "pending") {
    console.log(`[payment] PENDIENTE - ref: ${externalReference}`);
  } else if (status === "canceled" || status === "cancelled") {
    console.log(`[payment] CANCELADO - ref: ${externalReference}`);
  } else {
    console.log(`[payment] Estado desconocido: ${status}`);
  }

  let verifiedSubscription = null;
  // /v1/payments does not always echo the preapproval id. The authorized
  // payment invoice is an authenticated Mercado Pago resource and supplies
  // it as a safe fallback when this handler was reached through that topic.
  const preapprovalId = paymentPreapprovalId(result)
    || (preapprovalIdOverride ? String(preapprovalIdOverride) : null);
  if (preapprovalId) {
    verifiedSubscription = await mercadoPagoGet(
      "/preapproval/" + encodeURIComponent(preapprovalId)
    );
  }

  return updateSchoolFromPayment({
    paymentId: id,
    result,
    context,
    verifiedSubscription,
    preapprovalIdOverride,
  });
}

async function handleSubscriptionEvent(id, context) {
  const result = await mercadoPagoGet(`/preapproval/${id}`);
  const {
    status,
    reason,
    payer_email: payerEmail,
    external_reference: externalReference,
  } = result;

  console.log("[suscripcion] ID:", id);
  console.log("[suscripcion] Estado:", status);
  console.log("[suscripcion] Descripcion:", reason);
  console.log("[suscripcion] Pagador:", maskEmail(payerEmail));
  console.log("[suscripcion] Referencia:", externalReference);

  if (status === "authorized") {
    console.log(`[suscripcion] AUTORIZADA - ref: ${externalReference}`);
  } else if (status === "paused") {
    console.log(`[suscripcion] PAUSADA - ref: ${externalReference}`);
  } else if (status === "canceled" || status === "cancelled") {
    console.log(`[suscripcion] CANCELADA - ref: ${externalReference}`);
  } else {
    console.log(`[suscripcion] Estado desconocido: ${status}`);
  }

  return updateSchoolFromSubscription({ subscriptionId: id, result, context });
}

async function handleAuthorizedPaymentEvent(id, context) {
  const result = await mercadoPagoGet(`/authorized_payments/${id}`);

  console.log("[authorized_payment] ID:", id);
  console.log(
    "[authorized_payment] Estado:",
    result?.status || result?.status_detail || "sin estado"
  );
  console.log(
    "[authorized_payment] Referencia:",
    result?.external_reference || result?.metadata?.external_reference || null
  );

  const nestedPaymentId = result?.payment?.id;
  const authorizedPreapprovalId = result?.preapproval_id
    ? String(result.preapproval_id)
    : null;
  const authorizedSchoolId = await updateSchoolFromAuthorizedPayment({
    authorizedPaymentId: id,
    result,
    context,
    appendHistory: !nestedPaymentId,
  });

  if (nestedPaymentId) {
    const paymentSchoolId = await handlePaymentEvent(
      String(nestedPaymentId),
      context,
      authorizedPreapprovalId
    );
    return paymentSchoolId || authorizedSchoolId;
  }

  return authorizedSchoolId;
}

async function processWebhook(req) {
  logWebhookRequest(req);

  if (config.allowedWebhookIps.length > 0) {
    const sourceIp = getRequestIp(req);
    if (!config.allowedWebhookIps.includes(sourceIp)) {
      console.warn(`[webhook] IP no permitida: ${sourceIp}`);
      return;
    }
  }

  const context = buildEventContext(req);
  const signatureResult = validateSignature(req);

  if (!signatureResult.valid) {
    console.warn(
      `[webhook] Firma invalida (${signatureResult.reason}). Evento ignorado.`
    );

    try {
      await registerWebhookEvent({
        context,
        req,
        signatureResult,
        processingState: "ignored_invalid_signature",
        notes: signatureResult.reason,
      });
    } catch (err) {
      console.error("[webhook] Error guardando auditoria:", err.message);
    }

    return;
  }

  if (!context.resourceId) {
    console.warn("[webhook] No se encontro data.id en el payload");

    try {
      await registerWebhookEvent({
        context,
        req,
        signatureResult,
        processingState: "ignored_missing_resource_id",
        notes: "No se encontro data.id",
      });
    } catch (err) {
      console.error("[webhook] Error guardando auditoria:", err.message);
    }

    return;
  }

  let claimToken = null;
  let ownsClaim = false;

  try {
    const registration = await claimWebhookEvent({
      context,
      req,
      signatureResult,
    });

    if (registration.state === "processed") {
      console.log(`[webhook] Evento duplicado ignorado: ${context.eventKey}`);
      return;
    }

    if (registration.state !== "claimed") {
      throw new Error("El webhook ya esta siendo procesado");
    }
    claimToken = registration.claimToken;
    ownsClaim = true;

    let resolvedSchoolId = null;

    if (context.payloadType === "payment") {
      resolvedSchoolId = await handlePaymentEvent(context.resourceId, context);
    } else if (context.payloadType === "subscription_preapproval") {
      resolvedSchoolId = await handleSubscriptionEvent(context.resourceId, context);
    } else if (context.payloadType === "subscription_authorized_payment") {
      resolvedSchoolId = await handleAuthorizedPaymentEvent(
        context.resourceId,
        context
      );
    } else {
      console.log(`[webhook] Tipo de evento no manejado: ${context.payloadType}`);
    }

    const finalized = await finalizeWebhookEvent({
      context,
      claimToken,
      processingState: "processed",
      resolvedSchoolId,
      notes:
        context.payloadType === "payment" ||
        context.payloadType === "subscription_preapproval" ||
        context.payloadType === "subscription_authorized_payment"
          ? null
          : "Tipo de evento no manejado",
    });
    if (!finalized) {
      throw new Error("Se perdio la reclamacion del webhook antes de finalizarlo");
    }
  } catch (err) {
    console.error("[webhook] Error procesando evento:", err.message);

    if (ownsClaim) {
      try {
        await finalizeWebhookEvent({
          context,
          claimToken,
          processingState: "processing_error",
          notes: err.message,
        });
      } catch (auditErr) {
        console.error("[webhook] Error guardando auditoria:", auditErr.message);
      }
    }
    throw err;
  }
}

async function healthResponse() {
  try {
    await getMongoDb();
    return workerJson({
      status: "ok",
      mongo: "connected",
      https: "managed_by_cloudflare",
    });
  } catch (_err) {
    return workerJson({
      status: "error",
      mongo: "unavailable",
      https: "managed_by_cloudflare",
    }, 503);
  }
}

function workerJson(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function constantTimeEqual(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function isGatewayAuthorized(request) {
  const expected = config.gatewaySharedSecret;
  if (!expected) return config.nodeEnv !== "production";
  return constantTimeEqual(request.headers.get("x-gateway-secret") || "", expected);
}

async function workerRequest(request) {
  const url = new URL(request.url);
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return { error: workerJson({ error: "Content-Type debe ser application/json" }, 415) };
  }

  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > 32 * 1024) {
    return { error: workerJson({ error: "Payload demasiado grande" }, 413) };
  }

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return { error: workerJson({ error: "El cuerpo debe ser JSON válido" }, 400) };
  }

  const headers = Object.fromEntries(request.headers.entries());
  return {
    req: {
      headers,
      query: Object.fromEntries(url.searchParams.entries()),
      body,
      requestId: crypto.randomUUID(),
      ip: headers["cf-connecting-ip"] || headers["x-forwarded-for"]?.split(",")[0].trim() || "unknown",
    },
  };
}

export {
  entitlementDecisionFromPayment,
  entitlementDecisionFromPreapproval,
  extractBillingCycle,
  isVerifiedSubscriptionPayment,
  licenseStatusFromPayment,
  licenseStatusFromPreapproval,
  parseExternalReference,
};

export default {
  async fetch(request, env) {
    try {
      initialize(env);
    } catch (error) {
      console.error("[config] Worker no configurado:", error.message);
      return workerJson({ error: "Servicio no configurado" }, 503);
    }

    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/webhook/mercadopago") {
      const parsed = await workerRequest(request);
      if (parsed.error) return parsed.error;
      try {
        await processWebhook(parsed.req);
        return workerJson({ received: true });
      } catch (error) {
        console.error("[webhook] Procesamiento no confirmado:", error.message);
        return workerJson({ error: "No se pudo confirmar el procesamiento del webhook" }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/health") {
      if (!isGatewayAuthorized(request)) return workerJson({ error: "Acceso directo denegado" }, 403);
      return healthResponse();
    }

    return workerJson({ error: "Ruta no encontrada" }, 404);
  },
};
