import crypto from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";

const MERCADO_PAGO_API = "https://api.mercadopago.com";

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

  if (clone.authorization) clone.authorization = "[redacted]";
  if (clone.cookie) clone.cookie = "[redacted]";

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
        mongoState.db
          .collection("mercadopago_subscription_attempts")
          .createIndex({ subscriptionId: 1 }, { unique: true }),
        mongoState.db
          .collection("mercadopago_subscription_attempts")
          .createIndex({ externalReference: 1, updatedAt: -1 }),
        mongoState.db
          .collection("mercadopago_subscription_attempts")
          .createIndex({ schoolId: 1, updatedAt: -1 }),
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

function extractSchoolIdFromExternalReference(externalReference) {
  if (!externalReference) return null;

  const matches = String(externalReference).match(/[a-f0-9]{24}/gi);
  if (!matches || matches.length === 0) return null;

  const candidate = matches[matches.length - 1];
  if (!ObjectId.isValid(candidate)) return null;

  return candidate;
}

const PLAN_IDS = ["LOW_COST", "STANDARD", "FULL"];

// Formato actual: PLAN_CYCLE_EXTRAS_ATTEMPT_UUID_<24hexSchoolId>.
// También acepta el formato histórico PLAN_<24hexSchoolId>.
function extractCheckoutDetails(externalReference, reason) {
  if (!externalReference) return {};
  const ref = String(externalReference);
  const schoolId = extractSchoolIdFromExternalReference(ref);
  if (!schoolId || !ref.endsWith(`_${schoolId}`)) return {};
  const body = ref.slice(0, -(schoolId.length + 1));
  const planId = PLAN_IDS.find(
    (candidate) => body === candidate || body.startsWith(`${candidate}_`)
  );
  if (!planId) return { schoolId };

  const remainder = body === planId ? "" : body.slice(planId.length + 1);
  const parts = remainder.split("_").filter(Boolean);
  const cycleToken = parts[0]?.toLowerCase();
  const billingCycle = ["monthly", "annual"].includes(cycleToken)
    ? cycleToken
    : extractBillingCycleFromReason(reason);
  const extraCandidate = Number.parseInt(parts[1], 10);

  return {
    schoolId,
    planId,
    billingCycle,
    extraStudents: Number.isInteger(extraCandidate) && extraCandidate >= 0
      ? extraCandidate
      : 0,
    attemptId: parts.slice(2).join("_") || null,
  };
}

function extractPlanIdFromExternalReference(externalReference) {
  return extractCheckoutDetails(externalReference).planId || null;
}

// Deriva billingCycle del campo reason (ej: "FlyBoty LOW_COST · Anual")
function extractBillingCycleFromReason(reason) {
  if (!reason) return null;
  const r = String(reason).toLowerCase();
  if (r.includes("anual")) return "annual";
  if (r.includes("mensual")) return "monthly";
  return null;
}

function mapSubscriptionStatus(status) {
  switch (status) {
    case "authorized":
      // Autorización de débito no equivale a un pago acreditado.
      return "pending";
    case "paused":
      return "paused";
    case "cancelled":
    case "canceled":
      return "cancelled";
    case "pending":
      return "pending";
    default:
      return status || "inactive";
  }
}

function validDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function addCalendarMonths(value, months) {
  const date = validDate(value);
  if (!date) return null;
  const result = new Date(date);
  const originalDay = result.getUTCDate();
  result.setUTCDate(1);
  result.setUTCMonth(result.getUTCMonth() + months);
  const lastDay = new Date(
    Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0)
  ).getUTCDate();
  result.setUTCDate(Math.min(originalDay, lastDay));
  return result;
}

function paidPeriodEnd(school) {
  const canonical = validDate(school?.subscriptionCurrentPeriodEnd);
  const paymentId = school?.subscriptionLastSuccessfulPaymentId;
  const paidPreapprovalId =
    school?.subscriptionLastSuccessfulPaymentPreapprovalId;
  const currentPreapprovalId = school?.mercadoPagoSubscriptionId;
  if (!canonical || !paymentId || !paidPreapprovalId || !currentPreapprovalId) {
    return null;
  }
  return String(paidPreapprovalId) === String(currentPreapprovalId)
    ? canonical
    : null;
}

function hasPaidAccess(school, now = new Date()) {
  const end = paidPeriodEnd(school);
  return Boolean(end && end.getTime() > now.getTime());
}

function periodEndFromSubscription(preapproval, periodStart, billingCycle) {
  const start = validDate(periodStart);
  const frequency = Number(preapproval?.auto_recurring?.frequency);
  if (
    start &&
    preapproval?.auto_recurring?.frequency_type === "months" &&
    Number.isInteger(frequency) &&
    frequency > 0
  ) {
    return addCalendarMonths(start, frequency);
  }
  return addCalendarMonths(start, billingCycle === "annual" ? 12 : 1);
}

const ENTITLEMENT_REVOKING_PAYMENT_STATUSES = new Set([
  "refunded",
  "charged_back",
  "cancelled",
  "canceled",
]);

function normalizePaymentStatus(status) {
  return status === "canceled" ? "cancelled" : status || null;
}

function isEntitlementRevokingPaymentStatus(status) {
  return ENTITLEMENT_REVOKING_PAYMENT_STATUSES.has(String(status || ""));
}

function entitlementRevocationFields(
  school,
  {
    paymentId,
    preapprovalId,
    externalReference,
    status,
    eventAt,
  } = {}
) {
  const normalizedStatus = normalizePaymentStatus(status);
  if (!paymentId || !isEntitlementRevokingPaymentStatus(normalizedStatus)) {
    return null;
  }

  const grantedPaymentId = school?.subscriptionLastSuccessfulPaymentId;
  const grantedPreapprovalId =
    school?.subscriptionLastSuccessfulPaymentPreapprovalId;
  const currentPreapprovalId = school?.mercadoPagoSubscriptionId;
  if (
    !grantedPaymentId ||
    String(grantedPaymentId) !== String(paymentId) ||
    !grantedPreapprovalId ||
    !currentPreapprovalId ||
    String(grantedPreapprovalId) !== String(currentPreapprovalId) ||
    (preapprovalId &&
      String(preapprovalId) !== String(grantedPreapprovalId)) ||
    (externalReference &&
      school?.mercadoPagoExternalReference &&
      String(externalReference) !==
        String(school.mercadoPagoExternalReference))
  ) {
    return null;
  }

  const revokedAt = validDate(eventAt) || new Date();
  return {
    subscriptionEntitlementManaged: true,
    subscriptionStatus: "cancelled",
    subscriptionCurrentPeriodEnd: revokedAt,
    subscriptionNextPaymentDate: null,
    subscriptionCancelAtPeriodEnd: false,
    subscriptionEntitlementRevokedAt: revokedAt,
    subscriptionEntitlementRevocationStatus: normalizedStatus,
    subscriptionEntitlementRevokedPaymentId: String(paymentId),
    subscriptionEntitlementRevokedPreapprovalId: String(
      grantedPreapprovalId
    ),
  };
}

function pauseTransitionFields(
  school,
  providerStatus,
  { paidAccess = false, eventDate, receivedAt } = {}
) {
  const normalizedStatus =
    providerStatus === "canceled" ? "cancelled" : providerStatus;
  const providerModifiedAt = validDate(eventDate) || new Date();
  const observedAt = validDate(receivedAt) || providerModifiedAt;
  const currentProviderAt = validDate(
    school?.mercadoPagoSubscriptionProviderModifiedAt
  );
  const wasPaused = Boolean(
    school?.subscriptionPaused === true ||
      school?.mercadoPagoSubscriptionStatus === "paused"
  );
  const isStrictlyNewer = Boolean(
    !currentProviderAt ||
      providerModifiedAt.getTime() > currentProviderAt.getTime()
  );
  const legacyPauseCancellation = Boolean(
    wasPaused &&
      school?.subscriptionCancelAtPeriodEnd === true &&
      school?.mercadoPagoSubscriptionStatus === "paused"
  );

  if (normalizedStatus === "paused") {
    return {
      subscriptionStatus: paidAccess ? "active" : "paused",
      subscriptionPaused: true,
      subscriptionPausedAt:
        validDate(school?.subscriptionPausedAt) || observedAt,
      subscriptionRenews: false,
      subscriptionNextPaymentDate: null,
      ...(legacyPauseCancellation
        ? {
            subscriptionCancelAtPeriodEnd: false,
            subscriptionCancellationRequestedAt: null,
          }
        : {}),
    };
  }

  if (normalizedStatus === "authorized") {
    // A snapshot authorized anterior (o con la misma versión temporal) no
    // puede deshacer una pausa que ya fue observada.
    if (wasPaused && !isStrictlyNewer) return null;
    const renews =
      paidAccess &&
      !(school?.subscriptionCancelAtPeriodEnd && !legacyPauseCancellation);
    return {
      subscriptionStatus: paidAccess ? "active" : "pending",
      subscriptionPaused: false,
      subscriptionPausedAt: null,
      subscriptionRenews: renews,
      subscriptionNextPaymentDate: renews
        ? paidPeriodEnd(school)
        : null,
      ...(legacyPauseCancellation
        ? {
            subscriptionCancelAtPeriodEnd: false,
            subscriptionCancellationRequestedAt: null,
          }
        : {}),
    };
  }

  return {};
}

async function upsertSubscriptionAttempt(db, {
  subscriptionId,
  externalReference,
  reason,
  status,
  result,
  schoolId,
}) {
  const details = extractCheckoutDetails(externalReference, reason);
  const now = new Date();
  await db.collection("mercadopago_subscription_attempts").updateOne(
    { subscriptionId: String(subscriptionId) },
    {
      $set: {
        schoolId: String(schoolId),
        externalReference,
        reason: reason || null,
        status: status || null,
        planId: details.planId || null,
        billingCycle: details.billingCycle || null,
        extraStudents: details.extraStudents ?? 0,
        attemptId: details.attemptId || null,
        nextPaymentDate: validDate(result?.next_payment_date),
        frequency: result?.auto_recurring?.frequency ?? null,
        frequencyType: result?.auto_recurring?.frequency_type ?? null,
        providerLastModifiedAt: validDate(result?.last_modified),
        updatedAt: now,
      },
      $setOnInsert: { createdAt: now },
    },
    { upsert: true }
  );
  return { ...details, subscriptionId: String(subscriptionId) };
}

function buildSchoolEventEntry({
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

function revisionFilter(school) {
  const revision = Number(school?.mercadoPagoStateRevision);
  if (Number.isInteger(revision) && revision >= 0) {
    return { mercadoPagoStateRevision: revision };
  }
  return { mercadoPagoStateRevision: { $exists: false } };
}

async function updateSchoolAtomically(db, schoolId, buildUpdate) {
  const collection = db.collection("schools");
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const school = await collection.findOne({ _id: schoolId });
    if (!school) return null;
    const update = await buildUpdate(school);
    if (!update) return school;
    update.$inc = {
      ...(update.$inc || {}),
      mercadoPagoStateRevision: 1,
    };
    const result = await collection.updateOne(
      { _id: schoolId, ...revisionFilter(school) },
      update
    );
    if (result.modifiedCount === 1) return school;
  }
  throw new Error("Conflicto actualizando el estado de la suscripción");
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

  const result = await collection.updateOne(
    { eventKey: context.eventKey },
    {
      $setOnInsert: {
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
        processingState,
        processingStartedAt: new Date(),
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

  if (result.upsertedCount === 1) return { inserted: true, retry: false };

  // A processing failure must be retryable. The previous implementation made
  // the unique event key permanently suppress every Mercado Pago retry.
  const staleProcessingCutoff = new Date(Date.now() - 5 * 60 * 1000);
  const retryClaim = await collection.updateOne(
    {
      eventKey: context.eventKey,
      $or: [
        { processingState: "processing_error" },
        {
          processingState: "received",
          processingStartedAt: { $lt: staleProcessingCutoff },
        },
      ],
    },
    {
      $set: {
        processingState: "received",
        processingStartedAt: new Date(),
        notes: "Retrying after processing_error",
        updatedAt: new Date(),
      },
    }
  );
  return { inserted: retryClaim.modifiedCount === 1, retry: retryClaim.modifiedCount === 1 };
}

async function finalizeWebhookEvent({
  context,
  processingState,
  notes,
  resolvedSchoolId,
}) {
  const db = await getMongoDb();

  await db.collection("mercadopago_webhook_events").updateOne(
    { eventKey: context.eventKey },
    {
      $set: {
        processingState,
        notes: notes || null,
        resolvedSchoolId: resolvedSchoolId || null,
        processedAt: new Date(),
        updatedAt: new Date(),
      },
    }
  );
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

  const eventDate =
    validDate(result?.last_modified || result?.date_created) || new Date();
  const receivedAt = new Date();
  const db = await getMongoDb();
  const providerStatus = result?.status || null;
  const normalizedProviderStatus =
    providerStatus === "canceled" ? "cancelled" : providerStatus;
  const attempt = await upsertSubscriptionAttempt(db, {
    subscriptionId,
    externalReference,
    reason: result?.reason,
    status: normalizedProviderStatus,
    result,
    schoolId: resolved.schoolId,
  });
  await updateSchoolAtomically(db, resolved.school._id, (school) => {
    const currentSubscriptionId = school?.mercadoPagoSubscriptionId
      ? String(school.mercadoPagoSubscriptionId)
      : null;
    const isCurrentSubscription =
      currentSubscriptionId === String(subscriptionId);
    const paidAccessIsCurrent = hasPaidAccess(school, receivedAt);
    const currentProviderAt = validDate(
      school?.mercadoPagoSubscriptionProviderModifiedAt
    );
    const currentSubscriptionCreatedAt = validDate(
      school?.mercadoPagoCurrentSubscriptionCreatedAt
    );
    const providerCreatedAt = validDate(result?.date_created) || eventDate;
    const staleCurrentSnapshot = Boolean(
      isCurrentSubscription &&
        currentProviderAt &&
        eventDate.getTime() < currentProviderAt.getTime()
    );
    const olderDifferentCheckout = Boolean(
      currentSubscriptionId &&
        !isCurrentSubscription &&
        currentSubscriptionCreatedAt &&
        providerCreatedAt.getTime() <= currentSubscriptionCreatedAt.getTime()
    );

    const entitlementFields = {};
    if (!staleCurrentSnapshot && !paidAccessIsCurrent) {
      // Un mandato pending/authorized no compra acceso. Sólo seleccionamos el
      // intento más nuevo; la activación ocurre con una factura approved.
      if (
        ["pending", "authorized"].includes(normalizedProviderStatus) &&
        !olderDifferentCheckout
      ) {
        const transition = pauseTransitionFields(
          school,
          normalizedProviderStatus,
          {
            paidAccess: false,
            eventDate,
            receivedAt,
          }
        );
        if (transition !== null) {
          Object.assign(entitlementFields, {
            subscriptionEntitlementManaged: true,
            subscriptionStatus: "pending",
            mercadoPagoSubscriptionId: String(subscriptionId),
            mercadoPagoExternalReference: externalReference,
            mercadoPagoSubscriptionStatus: normalizedProviderStatus,
            mercadoPagoSubscriptionReason: result?.reason || null,
            mercadoPagoSubscriptionProviderModifiedAt: eventDate,
            mercadoPagoCurrentSubscriptionCreatedAt: providerCreatedAt,
            subscriptionRenews: false,
            subscriptionCancelAtPeriodEnd: false,
            ...transition,
          });
        }
      } else if (
        normalizedProviderStatus === "paused" &&
        (isCurrentSubscription || !currentSubscriptionId)
      ) {
        Object.assign(entitlementFields, {
          subscriptionEntitlementManaged: true,
          mercadoPagoSubscriptionStatus: normalizedProviderStatus,
          mercadoPagoSubscriptionProviderModifiedAt: eventDate,
          subscriptionCancelAtPeriodEnd: false,
          ...(pauseTransitionFields(school, normalizedProviderStatus, {
            paidAccess: false,
            eventDate,
            receivedAt,
          }) || {}),
        });
      } else if (
        normalizedProviderStatus === "cancelled" &&
        (isCurrentSubscription || !currentSubscriptionId)
      ) {
        Object.assign(entitlementFields, {
          subscriptionEntitlementManaged: true,
          subscriptionStatus: "cancelled",
          mercadoPagoSubscriptionStatus: normalizedProviderStatus,
          mercadoPagoSubscriptionProviderModifiedAt: eventDate,
          subscriptionRenews: false,
          subscriptionCancelAtPeriodEnd: false,
          subscriptionCancelledAt: receivedAt,
          subscriptionNextPaymentDate: null,
        });
      }
    } else if (
      !staleCurrentSnapshot &&
      paidAccessIsCurrent &&
      isCurrentSubscription
    ) {
      const providerFields = {
        subscriptionEntitlementManaged: true,
        mercadoPagoSubscriptionStatus: normalizedProviderStatus,
        mercadoPagoSubscriptionReason: result?.reason || null,
        mercadoPagoSubscriptionProviderModifiedAt: eventDate,
      };
      if (normalizedProviderStatus === "paused") {
        Object.assign(
          entitlementFields,
          providerFields,
          pauseTransitionFields(school, normalizedProviderStatus, {
            paidAccess: true,
            eventDate,
            receivedAt,
          }) || {}
        );
      } else if (normalizedProviderStatus === "cancelled") {
        Object.assign(entitlementFields, {
          ...providerFields,
          subscriptionStatus: "active",
          subscriptionRenews: false,
          subscriptionCancelAtPeriodEnd: true,
          subscriptionCancellationRequestedAt:
            school?.subscriptionCancellationRequestedAt || receivedAt,
          subscriptionNextPaymentDate: null,
        });
      } else if (normalizedProviderStatus === "authorized") {
        // Nunca copiar next_payment_date al período de acceso. Sólo un pago
        // aprobado puede extender subscriptionCurrentPeriodEnd.
        const transition = pauseTransitionFields(
          school,
          normalizedProviderStatus,
          { paidAccess: true, eventDate, receivedAt }
        );
        if (transition !== null) {
          Object.assign(entitlementFields, providerFields, transition);
        }
      }
    }

    return {
      $set: {
        mercadoPagoSchoolId: resolved.schoolId,
        mercadoPagoPayerEmail:
          result?.payer_email || school?.mercadoPagoPayerEmail || null,
        mercadoPagoLastWebhookAt: receivedAt,
        mercadoPagoLastEventType: context.payloadType,
        mercadoPagoLastEventAction: context.action,
        mercadoPagoLastSubscriptionId: String(subscriptionId),
        mercadoPagoLastSubscriptionStatus: normalizedProviderStatus,
        mercadoPagoLastSubscriptionExternalReference: externalReference,
        mercadoPagoLastSubscriptionVersion: String(result?.version ?? context.version),
        mercadoPagoCheckout: {
          subscriptionId: String(subscriptionId),
          status: normalizedProviderStatus,
          externalReference,
          planName: attempt.planId || null,
          billingCycle: attempt.billingCycle || null,
          extraStudents: attempt.extraStudents ?? 0,
          attemptId: attempt.attemptId || null,
          updatedAt: receivedAt,
        },
        mercadoPagoSubscriptionLastEventAt: new Date(eventDate),
        ...entitlementFields,
        updatedAt: new Date(),
      },
      $push: {
        mercadoPagoEventHistory: {
          $each: [
            buildSchoolEventEntry({
              sourceType: context.payloadType,
              sourceId: subscriptionId,
              action: context.action,
              status: normalizedProviderStatus,
              externalReference,
              receivedAt,
              rawEventId: context.notificationId,
            }),
          ],
          $slice: -30,
        },
      },
    };
  });

  return resolved.schoolId;
}

async function updateSchoolFromPayment({
  paymentId,
  result,
  context,
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
  const paymentEventAt =
    validDate(
      result?.date_last_updated ||
        result?.date_approved ||
        result?.date_created
    ) || receivedAt;
  const db = await getMongoDb();
  await updateSchoolAtomically(db, resolved.school._id, (school) => {
    const previousPaymentEventAt = validDate(
      school?.mercadoPagoLastPaymentEventAt
    );
    const isLatestPaymentEvent =
      !previousPaymentEventAt ||
      paymentEventAt.getTime() >= previousPaymentEventAt.getTime();
    const latestPaymentFields = isLatestPaymentEvent
      ? {
          mercadoPagoPayerEmail:
            result?.payer?.email || school?.mercadoPagoPayerEmail || null,
          mercadoPagoLastPaymentId: String(paymentId),
          mercadoPagoLastPaymentStatus: result?.status || null,
          mercadoPagoLastPaymentStatusDetail: result?.status_detail || null,
          mercadoPagoLastPaymentAmount: result?.transaction_amount ?? null,
          mercadoPagoLastPaymentCurrency: result?.currency_id || null,
          mercadoPagoLastPaymentDateCreated: validDate(result?.date_created),
          mercadoPagoLastPaymentDateApproved: validDate(result?.date_approved),
          mercadoPagoLastPaymentEventAt: paymentEventAt,
        }
      : {};
    const revocationFields = entitlementRevocationFields(school, {
      paymentId,
      externalReference,
      status: result?.status,
      eventAt: paymentEventAt,
    });

    return {
      $set: {
        mercadoPagoSchoolId: resolved.schoolId,
        mercadoPagoLastWebhookAt: receivedAt,
        mercadoPagoLastEventType: context.payloadType,
        mercadoPagoLastEventAction: context.action,
        ...latestPaymentFields,
        ...(revocationFields || {}),
        updatedAt: receivedAt,
      },
      $push: {
        mercadoPagoEventHistory: {
          $each: [
            buildSchoolEventEntry({
              sourceType: context.payloadType,
              sourceId: String(paymentId),
              action: context.action,
              status: result?.status,
              amount: result?.transaction_amount,
              externalReference,
              receivedAt,
              rawEventId: context.notificationId,
            }),
          ],
          $slice: -30,
        },
      },
    };
  });

  return resolved.schoolId;
}

async function updateSchoolFromAuthorizedPayment({
  authorizedPaymentId,
  result,
  preapproval,
  payment,
  context,
}) {
  const externalReference =
    preapproval?.external_reference ||
    payment?.external_reference ||
    result?.external_reference ||
    result?.metadata?.external_reference ||
    result?.reason;
  if (
    preapproval?.external_reference &&
    payment?.external_reference &&
    preapproval.external_reference !== payment.external_reference
  ) {
    throw new Error("La factura no pertenece al preapproval informado");
  }
  const resolved = await findSchoolByExternalReference(externalReference);

  if (!resolved) {
    console.warn(
      `[authorized_payment] No se encontro escuela para external_reference: ${externalReference}`
    );
    return null;
  }

  const receivedAt = new Date();
  const db = await getMongoDb();
  const subscriptionId = result?.preapproval_id || preapproval?.id || null;
  const providerStatusRaw = preapproval?.status || null;
  const providerStatus = providerStatusRaw === "canceled" ? "cancelled" : providerStatusRaw;
  let attempt = null;
  if (subscriptionId) {
    attempt = await upsertSubscriptionAttempt(db, {
      subscriptionId,
      externalReference,
      reason: preapproval?.reason || result?.reason,
      status: providerStatus,
      result: preapproval || result,
      schoolId: resolved.schoolId,
    });
  }
  const nestedPaymentStatus = payment?.status || result?.payment?.status || null;
  const nestedPaymentId = payment?.id
    ? String(payment.id)
    : result?.payment?.id
      ? String(result.payment.id)
      : null;
  const isApproved = nestedPaymentStatus === "approved";
  const approvedAt =
    validDate(payment?.date_approved) ||
    validDate(result?.date_created) ||
    receivedAt;
  const periodStart =
    validDate(result?.debit_date) || validDate(payment?.date_created) || approvedAt;
  const details = extractCheckoutDetails(
    externalReference,
    preapproval?.reason || result?.reason
  );
  const billingCycle = attempt?.billingCycle || details.billingCycle || "monthly";
  const periodEnd = periodEndFromSubscription(
    preapproval,
    periodStart,
    billingCycle
  );

  await updateSchoolAtomically(db, resolved.school._id, (school) => {
    const currentSubscriptionId = school?.mercadoPagoSubscriptionId
      ? String(school.mercadoPagoSubscriptionId)
      : null;
    const sameCurrentSubscription = Boolean(
      subscriptionId && currentSubscriptionId === String(subscriptionId)
    );
    const providerCreatedAt =
      validDate(preapproval?.date_created) || approvedAt;
    const currentSubscriptionCreatedAt = validDate(
      school?.mercadoPagoCurrentSubscriptionCreatedAt ||
        school?.subscriptionActivatedAt ||
        school?.LastAprovedPaymentDate
    );
    const belongsToNewestSubscription = Boolean(
      subscriptionId &&
        (!currentSubscriptionId ||
          sameCurrentSubscription ||
          !currentSubscriptionCreatedAt ||
          providerCreatedAt.getTime() > currentSubscriptionCreatedAt.getTime())
    );
    const previousApprovedAt = validDate(
      school?.subscriptionLastSuccessfulPaymentAt ||
        school?.LastAprovedPaymentDate
    );
    const sameSuccessfulPayment = Boolean(
      nestedPaymentId &&
        String(school?.subscriptionLastSuccessfulPaymentId || "") ===
          nestedPaymentId
    );
    const isNewestInvoice = Boolean(
      sameSuccessfulPayment ||
        !previousApprovedAt ||
        approvedAt.getTime() >= previousApprovedAt.getTime()
    );
    const shouldPromotePayment = Boolean(
      isApproved &&
        nestedPaymentId &&
        subscriptionId &&
        periodEnd &&
        periodEnd.getTime() > receivedAt.getTime() &&
        belongsToNewestSubscription &&
        isNewestInvoice
    );
    const entitlementFields =
      entitlementRevocationFields(school, {
        paymentId: nestedPaymentId,
        preapprovalId: subscriptionId,
        externalReference,
        status: nestedPaymentStatus,
        eventAt:
          payment?.date_last_updated ||
          payment?.date_approved ||
          result?.date_created ||
          receivedAt,
      }) || {};

    if (shouldPromotePayment) {
      const providerPaused = providerStatus === "paused";
      const cancellationAlreadyRequested = Boolean(
        (school?.subscriptionCancelAtPeriodEnd && sameCurrentSubscription) ||
          providerStatus === "cancelled"
      );
      const resolvedExtraStudents = sameCurrentSubscription
        ? Number(school?.extraStudents ?? attempt?.extraStudents ?? 0)
        : Number(attempt?.extraStudents ?? details.extraStudents ?? 0);
      Object.assign(entitlementFields, {
        subscriptionEntitlementManaged: true,
        subscriptionStatus: "active",
        subscriptionActivatedAt: school?.subscriptionActivatedAt || approvedAt,
        subscriptionCurrentPeriodStart: periodStart,
        subscriptionCurrentPeriodEnd: periodEnd,
        subscriptionNextPaymentDate:
          cancellationAlreadyRequested || providerPaused
          ? null
          : periodEnd,
        subscriptionRenews:
          !cancellationAlreadyRequested && !providerPaused,
        subscriptionCancelAtPeriodEnd: cancellationAlreadyRequested,
        subscriptionCancellationRequestedAt: cancellationAlreadyRequested
          ? school?.subscriptionCancellationRequestedAt || receivedAt
          : null,
        subscriptionCancelledAt: null,
        subscriptionPaused: providerPaused,
        subscriptionPausedAt: providerPaused
          ? school?.subscriptionPausedAt || receivedAt
          : null,
        subscriptionLastSuccessfulPaymentId: nestedPaymentId,
        subscriptionLastSuccessfulPaymentPreapprovalId: String(subscriptionId),
        subscriptionLastSuccessfulPaymentAt: approvedAt,
        LastAprovedPaymentDate: approvedAt,
        LastAprovedAmount:
          payment?.transaction_amount ?? result?.transaction_amount ?? null,
        mercadoPagoLastPaymentId: nestedPaymentId,
        mercadoPagoLastPaymentStatus: nestedPaymentStatus,
        mercadoPagoLastPaymentStatusDetail:
          payment?.status_detail || result?.payment?.status_detail || null,
        mercadoPagoLastPaymentAmount:
          payment?.transaction_amount ?? result?.transaction_amount ?? null,
        mercadoPagoLastPaymentCurrency:
          payment?.currency_id || result?.currency_id || null,
        mercadoPagoLastPaymentDateCreated:
          validDate(payment?.date_created) || periodStart,
        mercadoPagoLastPaymentDateApproved: approvedAt,
        mercadoPagoLastPaymentEventAt: approvedAt,
        mercadoPagoExternalReference: externalReference,
        mercadoPagoSubscriptionId: String(subscriptionId),
        mercadoPagoSubscriptionStatus: providerStatus || "authorized",
        mercadoPagoSubscriptionReason:
          preapproval?.reason || result?.reason || null,
        mercadoPagoSubscriptionProviderModifiedAt:
          validDate(preapproval?.last_modified) || receivedAt,
        mercadoPagoCurrentSubscriptionCreatedAt: providerCreatedAt,
        planName:
          attempt?.planId || details.planId || school?.planName || null,
        billingCycle,
        extraStudents: resolvedExtraStudents,
        maxStudents: 50 + resolvedExtraStudents,
      });
    }

    const previousAuthorizedEventAt = validDate(
      school?.mercadoPagoLastAuthorizedPaymentEventAt
    );
    const authorizedEventAt =
      validDate(result?.date_created) || approvedAt || receivedAt;
    const latestAuthorizedFields =
      !previousAuthorizedEventAt ||
      authorizedEventAt.getTime() >= previousAuthorizedEventAt.getTime()
        ? {
            mercadoPagoLastAuthorizedPaymentId: String(authorizedPaymentId),
            mercadoPagoLastAuthorizedPaymentStatus:
              result?.status ||
              result?.status_detail ||
              nestedPaymentStatus ||
              "received",
            mercadoPagoLastAuthorizedPaymentDate: authorizedEventAt,
            mercadoPagoLastAuthorizedPaymentEventAt: authorizedEventAt,
            mercadoPagoLastAuthorizedPaymentPreapprovalId: subscriptionId
              ? String(subscriptionId)
              : null,
            mercadoPagoLastAuthorizedPaymentPaymentId: nestedPaymentId,
            mercadoPagoLastAuthorizedPaymentPaymentStatus:
              nestedPaymentStatus,
          }
        : {};

    return {
      $set: {
        mercadoPagoSchoolId: resolved.schoolId,
        mercadoPagoLastWebhookAt: receivedAt,
        mercadoPagoLastEventType: context.payloadType,
        mercadoPagoLastEventAction: context.action,
        ...latestAuthorizedFields,
        ...entitlementFields,
        updatedAt: receivedAt,
      },
      $push: {
        mercadoPagoEventHistory: {
          $each: [
            buildSchoolEventEntry({
              sourceType: context.payloadType,
              sourceId: String(authorizedPaymentId),
              action: context.action,
              status: result?.status || result?.status_detail || "received",
              externalReference,
              receivedAt,
              rawEventId: context.notificationId,
            }),
          ],
          $slice: -30,
        },
      },
    };
  });

  return resolved.schoolId;
}

async function handlePaymentEvent(id, context) {
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
  console.log("[payment] Pagador:", payer?.email);

  if (status === "approved") {
    console.log(`[payment] APROBADO - ref: ${externalReference}`);
  } else if (status === "rejected") {
    console.log(`[payment] RECHAZADO (${statusDetail}) - ref: ${externalReference}`);
  } else if (status === "pending") {
    console.log(`[payment] PENDIENTE - ref: ${externalReference}`);
  } else if (status === "cancelled") {
    console.log(`[payment] CANCELADO - ref: ${externalReference}`);
  } else {
    console.log(`[payment] Estado desconocido: ${status}`);
  }

  return updateSchoolFromPayment({ paymentId: id, result, context });
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
  console.log("[suscripcion] Pagador:", payerEmail);
  console.log("[suscripcion] Referencia:", externalReference);

  if (status === "authorized") {
    console.log(`[suscripcion] AUTORIZADA - ref: ${externalReference}`);
  } else if (status === "paused") {
    console.log(`[suscripcion] PAUSADA - ref: ${externalReference}`);
  } else if (status === "cancelled") {
    console.log(`[suscripcion] CANCELADA - ref: ${externalReference}`);
  } else {
    console.log(`[suscripcion] Estado desconocido: ${status}`);
  }

  return updateSchoolFromSubscription({ subscriptionId: id, result, context });
}

async function handleAuthorizedPaymentEvent(id, context) {
  const result = await mercadoPagoGet(`/authorized_payments/${id}`);
  const preapproval = result?.preapproval_id
    ? await mercadoPagoGet(`/preapproval/${result.preapproval_id}`)
    : null;
  const payment = result?.payment?.id
    ? await mercadoPagoGet(`/v1/payments/${result.payment.id}`)
    : null;

  console.log("[authorized_payment] ID:", id);
  console.log(
    "[authorized_payment] Estado:",
    result?.status || result?.status_detail || "sin estado"
  );
  console.log(
    "[authorized_payment] Referencia:",
    result?.external_reference || result?.metadata?.external_reference || null
  );

  return updateSchoolFromAuthorizedPayment({
    authorizedPaymentId: id,
    result,
    preapproval,
    payment,
    context,
  });
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

  try {
    const registration = await registerWebhookEvent({
      context,
      req,
      signatureResult,
      processingState: "received",
      notes: null,
    });

    if (!registration.inserted) {
      console.log(`[webhook] Evento duplicado ignorado: ${context.eventKey}`);
      return;
    }

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

    await finalizeWebhookEvent({
      context,
      processingState: "processed",
      resolvedSchoolId,
      notes:
        context.payloadType === "payment" ||
        context.payloadType === "subscription_preapproval" ||
        context.payloadType === "subscription_authorized_payment"
          ? null
          : "Tipo de evento no manejado",
    });
  } catch (err) {
    console.error("[webhook] Error procesando evento:", err.message);

    try {
      await finalizeWebhookEvent({
        context,
        processingState: "processing_error",
        notes: err.message,
      });
    } catch (auditErr) {
      console.error("[webhook] Error guardando auditoria:", auditErr.message);
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

export default {
  async fetch(request, env, ctx) {
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
      } catch (_error) {
        // El 5xx hace que Mercado Pago reintente; el evento quedó marcado como
        // processing_error y puede ser reclamado de forma idempotente.
        return workerJson({ error: "No se pudo procesar el webhook" }, 503);
      }
    }

    if (request.method === "GET" && url.pathname === "/health") {
      if (!isGatewayAuthorized(request)) return workerJson({ error: "Acceso directo denegado" }, 403);
      return healthResponse();
    }

    return workerJson({ error: "Ruta no encontrada" }, 404);
  },
};

export {
  addCalendarMonths,
  entitlementRevocationFields,
  extractCheckoutDetails,
  hasPaidAccess,
  mapSubscriptionStatus,
  pauseTransitionFields,
  periodEndFromSubscription,
};
