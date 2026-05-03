require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { MongoClient, ObjectId } = require("mongodb");
const {
  Invoice,
  MercadoPagoConfig,
  Payment,
  PreApproval,
} = require("mercadopago");

const config = loadConfig();
validateConfig(config);

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", config.trustProxy);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: "no-referrer" },
    hsts: config.requireHttps
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
  })
);

app.use(express.json({ limit: config.maxBodySize, type: "application/json" }));
app.use(express.urlencoded({ extended: false, limit: config.maxBodySize }));

if (config.requireHttps) {
  app.use((req, res, next) => {
    if (req.secure || req.headers["x-forwarded-proto"] === "https") {
      return next();
    }

    if (req.method === "GET" || req.method === "HEAD") {
      const host = req.headers.host || "localhost";
      return res.redirect(301, `https://${host}${req.originalUrl}`);
    }

    return res.status(426).json({ error: "HTTPS requerido" });
  });
}

app.use("/health", buildRateLimiter("health", config.healthRateLimit));
app.use("/webhook/mercadopago", buildRateLimiter("webhook", config.webhookRateLimit));

app.use((req, _res, next) => {
  req.requestId = crypto.randomUUID();
  next();
});

const mpClient = new MercadoPagoConfig({ accessToken: config.mpAccessToken });
const paymentClient = new Payment(mpClient);
const preApprovalClient = new PreApproval(mpClient);
const invoiceClient = new Invoice(mpClient);

const mongoState = {
  client: null,
  db: null,
  connecting: null,
  indexesReady: false,
};

function loadConfig() {
  return {
    nodeEnv: process.env.NODE_ENV || "development",
    port: parseInteger(process.env.PORT, 3400),
    httpsPort: parseInteger(process.env.HTTPS_PORT, 3443),
    httpsEnabled: parseBoolean(process.env.HTTPS_ENABLED, false),
    sslKeyPath: process.env.SSL_KEY_PATH || "",
    sslCertPath: process.env.SSL_CERT_PATH || "",
    trustProxy: parseProxyValue(process.env.TRUST_PROXY),
    requireHttps: parseBoolean(process.env.REQUIRE_HTTPS, false),
    maxBodySize: process.env.MAX_BODY_SIZE || "32kb",
    signatureMaxAgeSeconds: parseInteger(
      process.env.SIGNATURE_MAX_AGE_SECONDS,
      300
    ),
    webhookRateLimit: {
      windowMs: parseInteger(process.env.WEBHOOK_RATE_LIMIT_WINDOW_MS, 60000),
      max: parseInteger(process.env.WEBHOOK_RATE_LIMIT_MAX, 120),
    },
    healthRateLimit: {
      windowMs: parseInteger(process.env.HEALTH_RATE_LIMIT_WINDOW_MS, 60000),
      max: parseInteger(process.env.HEALTH_RATE_LIMIT_MAX, 30),
    },
    webhookEventRetentionDays: parseInteger(
      process.env.WEBHOOK_EVENT_RETENTION_DAYS,
      90
    ),
    logWebhookPayloads: parseBoolean(process.env.LOG_WEBHOOK_PAYLOADS, false),
    allowedWebhookIps: parseCsv(process.env.ALLOWED_WEBHOOK_IPS),
    mongodbUri: process.env.MONGODB_URI,
    mongodbDb: process.env.MONGODB_DB || "FlyBotyInstruccion",
    mpAccessToken: process.env.MP_ACCESS_TOKEN,
    mpWebhookSecret: process.env.MP_WEBHOOK_SECRET,
  };
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

  if (currentConfig.httpsEnabled) {
    if (!currentConfig.sslKeyPath || !currentConfig.sslCertPath) {
      throw new Error(
        "HTTPS_ENABLED=true requiere SSL_KEY_PATH y SSL_CERT_PATH en el .env"
      );
    }

    if (!fs.existsSync(currentConfig.sslKeyPath)) {
      throw new Error(`No existe SSL_KEY_PATH: ${currentConfig.sslKeyPath}`);
    }

    if (!fs.existsSync(currentConfig.sslCertPath)) {
      throw new Error(`No existe SSL_CERT_PATH: ${currentConfig.sslCertPath}`);
    }
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

function buildRateLimiter(name, options) {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: `Rate limit excedido para ${name}` },
  });
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

app.post("/webhook/mercadopago", async (req, res) => {
  logWebhookRequest(req);

  if (!req.is("application/json")) {
    return res.status(415).json({ error: "Content-Type debe ser application/json" });
  }

  if (config.allowedWebhookIps.length > 0) {
    const sourceIp = getRequestIp(req);
    if (!config.allowedWebhookIps.includes(sourceIp)) {
      console.warn(`[webhook] IP no permitida: ${sourceIp}`);
      return res.status(403).json({ error: "IP no permitida" });
    }
  }

  const context = buildEventContext(req);
  const signatureResult = validateSignature(req);

  res.status(200).json({ received: true });

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
});

app.get("/health", async (_req, res) => {
  try {
    await getMongoDb();
    return res.json({
      status: "ok",
      mongo: "connected",
      https: config.httpsEnabled || config.requireHttps ? "enabled" : "disabled",
    });
  } catch (_err) {
    return res.status(503).json({
      status: "error",
      mongo: "unavailable",
      https: config.httpsEnabled || config.requireHttps ? "enabled" : "disabled",
    });
  }
});

function startServers() {
  let mainServer;
  let redirectServer = null;

  if (config.httpsEnabled) {
    const sslOptions = {
      key: fs.readFileSync(config.sslKeyPath),
      cert: fs.readFileSync(config.sslCertPath),
      minVersion: "TLSv1.2",
      honorCipherOrder: true,
    };

    mainServer = https.createServer(sslOptions, app);
    mainServer.listen(config.httpsPort, () => {
      console.log(`Webhook HTTPS escuchando en https://localhost:${config.httpsPort}`);
      console.log(
        `  POST https://localhost:${config.httpsPort}/webhook/mercadopago`
      );
      console.log(`  GET  https://localhost:${config.httpsPort}/health`);
    });

    redirectServer = http.createServer((req, res) => {
      const host = (req.headers.host || "localhost").replace(/:\d+$/, "");
      res.writeHead(301, {
        Location: `https://${host}:${config.httpsPort}${req.url}`,
      });
      res.end();
    });

    redirectServer.listen(config.port, () => {
      console.log(`Redireccion HTTP -> HTTPS activa en http://localhost:${config.port}`);
    });
  } else {
    mainServer = http.createServer(app);
    mainServer.listen(config.port, () => {
      console.log(`Webhook escuchando en http://localhost:${config.port}`);
      console.log(`  POST http://localhost:${config.port}/webhook/mercadopago`);
      console.log(`  GET  http://localhost:${config.port}/health`);
    });
  }

  return { mainServer, redirectServer };
}

async function bootstrap() {
  await getMongoDb();
  const { mainServer, redirectServer } = startServers();

  const shutdown = async (signal) => {
    console.log(`Cerrando webhook (${signal})`);

    if (redirectServer) {
      await new Promise((resolve) => redirectServer.close(resolve));
    }

    await new Promise((resolve) => mainServer.close(resolve));
    await closeMongo();
    process.exit(0);
  };

  process.on("SIGINT", () => {
    shutdown("SIGINT").catch((err) => {
      console.error("Error cerrando servidor:", err.message);
      process.exit(1);
    });
  });

  process.on("SIGTERM", () => {
    shutdown("SIGTERM").catch((err) => {
      console.error("Error cerrando servidor:", err.message);
      process.exit(1);
    });
  });
}

bootstrap().catch((err) => {
  console.error("No se pudo iniciar el webhook:", err.message);
  process.exit(1);
});
