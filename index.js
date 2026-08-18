import crypto from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";
import {
  Invoice,
  MercadoPagoConfig,
  Payment,
  PreApproval,
} from "mercadopago";

let config;
let paymentClient;
let preApprovalClient;
let invoiceClient;

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
  const mpClient = new MercadoPagoConfig({ accessToken: loadedConfig.mpAccessToken });
  paymentClient = new Payment(mpClient);
  preApprovalClient = new PreApproval(mpClient);
  invoiceClient = new Invoice(mpClient);
  config = loadedConfig;
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

// Extrae el planId del external_reference con formato "PLAN_ID_<24hexSchoolId>"
function extractPlanIdFromExternalReference(externalReference) {
  if (!externalReference) return null;
  const ref = String(externalReference);
  const schoolId = extractSchoolIdFromExternalReference(ref);
  if (!schoolId) return null;
  // planId es todo lo que está antes de "_<schoolId>"
  const planId = ref.slice(0, ref.length - schoolId.length - 1);
  return planId || null;
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
      return "active";
    case "paused":
      return "paused";
    case "cancelled":
      return "cancelled";
    case "pending":
      return "pending";
    default:
      return status || "inactive";
  }
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

  const eventDate = result?.last_modified || result?.date_created || new Date();
  const receivedAt = new Date();
  const db = await getMongoDb();

  const parsedPlanId = extractPlanIdFromExternalReference(externalReference);
  const parsedBillingCycle = extractBillingCycleFromReason(result?.reason);
  const nextPaymentDate = result?.next_payment_date
    ? new Date(result.next_payment_date)
    : result?.auto_recurring?.end_date
    ? new Date(result.auto_recurring.end_date)
    : null;

  const planFields = {};
  if (parsedPlanId) planFields.planName = parsedPlanId;
  if (parsedBillingCycle) planFields.billingCycle = parsedBillingCycle;
  if (nextPaymentDate) planFields.subscriptionNextPaymentDate = nextPaymentDate;

  await db.collection("schools").updateOne(
    { _id: resolved.school._id },
    {
      $set: {
        mercadoPagoExternalReference: externalReference,
        mercadoPagoSchoolId: resolved.schoolId,
        mercadoPagoPayerEmail:
          result?.payer_email || resolved.school?.mercadoPagoPayerEmail || null,
        mercadoPagoLastWebhookAt: receivedAt,
        mercadoPagoLastEventType: context.payloadType,
        mercadoPagoLastEventAction: context.action,
        mercadoPagoSubscriptionId: subscriptionId,
        mercadoPagoSubscriptionStatus: result?.status || null,
        mercadoPagoSubscriptionReason: result?.reason || null,
        mercadoPagoSubscriptionVersion: context.version,
        mercadoPagoSubscriptionLastEventAt: new Date(eventDate),
        subscriptionStatus: mapSubscriptionStatus(result?.status),
        ...planFields,
        updatedAt: new Date(),
      },
      $push: {
        mercadoPagoEventHistory: {
          $each: [
            buildSchoolEventEntry({
              sourceType: context.payloadType,
              sourceId: subscriptionId,
              action: context.action,
              status: result?.status,
              externalReference,
              receivedAt,
              rawEventId: context.notificationId,
            }),
          ],
          $slice: -30,
        },
      },
    }
  );

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
  const isApproved = result?.status === "approved";
  const approvedDate = result?.date_approved
    ? new Date(result.date_approved)
    : receivedAt;

  const update = {
    mercadoPagoExternalReference: externalReference,
    mercadoPagoSchoolId: resolved.schoolId,
    mercadoPagoPayerEmail:
      result?.payer?.email || resolved.school?.mercadoPagoPayerEmail || null,
    mercadoPagoLastWebhookAt: receivedAt,
    mercadoPagoLastEventType: context.payloadType,
    mercadoPagoLastEventAction: context.action,
    mercadoPagoLastPaymentId: String(paymentId),
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

  if (isApproved) {
    update.LastAprovedPaymentDate = approvedDate;
    update.LastAprovedAmount = result?.transaction_amount ?? null;
  }

  await (await getMongoDb()).collection("schools").updateOne(
    { _id: resolved.school._id },
    {
      $set: update,
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
    }
  );

  return resolved.schoolId;
}

async function updateSchoolFromAuthorizedPayment({
  authorizedPaymentId,
  result,
  context,
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

  await (await getMongoDb()).collection("schools").updateOne(
    { _id: resolved.school._id },
    {
      $set: {
        mercadoPagoExternalReference:
          externalReference || resolved.school?.mercadoPagoExternalReference || null,
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
    }
  );

  return resolved.schoolId;
}

async function handlePaymentEvent(id, context) {
  const result = await paymentClient.get({ id });
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
  const result = await preApprovalClient.get({ id });
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
  const result = await invoiceClient.get({ id });

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
      // Mercado Pago only needs an acknowledgement. Keep the database/API work
      // alive after responding, so retries are not caused by normal processing time.
      ctx.waitUntil(processWebhook(parsed.req));
      return workerJson({ received: true });
    }

    if (request.method === "GET" && url.pathname === "/health") {
      if (!isGatewayAuthorized(request)) return workerJson({ error: "Acceso directo denegado" }, 403);
      return healthResponse();
    }

    return workerJson({ error: "Ruta no encontrada" }, 404);
  },
};
