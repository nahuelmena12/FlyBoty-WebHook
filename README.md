# FlyBoty Mercado Pago Webhook

Webhook de Mercado Pago ejecutado como Cloudflare Worker. Valida `x-signature`, consulta el recurso con la API de Mercado Pago y guarda el evento y el estado resultante en MongoDB Atlas.

## Rutas

| Método | Ruta | Acceso |
| --- | --- | --- |
| POST | `/webhook/mercadopago` | Público para Mercado Pago; la firma es obligatoria y se valida antes de procesar. |
| GET | `/health` | Requiere `x-gateway-secret` en producción. |

No protejas la URL de webhook con JWT ni con `x-gateway-secret`: Mercado Pago no los envía. La seguridad de esa ruta es `x-signature` + `x-request-id` + `MP_WEBHOOK_SECRET` + límite de antigüedad de firma.

## Variables de producción

En **Workers & Pages > flyboty-mercadopago-webhook > Settings > Variables and Secrets > Production** configurá:

| Nombre | Tipo | Valor |
| --- | --- | --- |
| `MONGODB_URI` | Secret | URI de conexión de MongoDB Atlas |
| `MP_ACCESS_TOKEN` | Secret | Access Token de Mercado Pago |
| `MP_WEBHOOK_SECRET` | Secret | Clave secreta de validación de webhooks de Mercado Pago |
| `GATEWAY_SHARED_SECRET` | Secret | El mismo secreto del API Gateway; protege `/health` |
| `MONGODB_DB` | Variable | `FlyBotyInstruccion` |
| `ENVIRONMENT` | Variable | `production` |
| `SIGNATURE_MAX_AGE_SECONDS` | Variable | `300` |
| `WEBHOOK_EVENT_RETENTION_DAYS` | Variable | `90` |
| `LOG_WEBHOOK_PAYLOADS` | Variable | `false` |
| `ALLOWED_WEBHOOK_IPS` | Variable | Vacío, salvo que mantengas una lista de IPs actualizada de Mercado Pago |

Cloudflare gestiona HTTPS y certificados. No configures `PORT`, `HOST`, `HTTPS_ENABLED`, `SSL_KEY_PATH` ni `SSL_CERT_PATH`.

## Activación de licencia

El webhook guarda la preaprobación como trazabilidad, pero no concede acceso por su estado authorized. La licencia se habilita solamente después de consultar el recurso payment y confirmar que su estado es approved, que corresponde a la preaprobación y que coincide con la referencia, moneda e importe generados por el servidor. Los estados pending, canceled/cancelled, rejected, paused, refunded y charged_back nunca activan una licencia.

Las referencias nuevas usan el formato versionado `flyboty:v2:...`; incluyen el plan, ciclo, capacidad e importe calculados por el Worker. Al aprobarse el pago, el webhook aplica esos alumnos extra y `maxStudents` de forma atómica. No expongas una ruta administrativa que modifique la capacidad directamente.

Configurá en Mercado Pago los tópicos payment, subscription_preapproval y subscription_authorized_payment. El tópico payment es la fuente de verdad para acreditar cada cobro.

Las referencias históricas `v1` y `PLAN_<schoolId>` se procesan sólo como auditoría: no pueden otorgar acceso ni capacidad. Una baja histórica se aplica únicamente si su `preapproval_id` coincide exactamente con el ID ya guardado en la escuela. Antes del deploy, verificá o completá `mercadoPagoSubscriptionId`/`mercadoPagoActiveSubscriptionId` para las suscripciones antiguas que deban seguir pudiendo darse de baja.

## Deploy

```bash
npm ci
npm run deploy
```

Para Git integration: **Build command** `npm ci`, **Deploy command** `npm run deploy`, raíz `/`.

## Dominio y configuración en Mercado Pago

Asigná el dominio `webhook.flyboty.com` desde **Settings > Domains & Routes** y configurá en Mercado Pago esta URL de notificación:

```text
https://webhook.flyboty.com/webhook/mercadopago
```

En MongoDB Atlas, autorizá el acceso desde Cloudflare según la política de red de tu cluster. El Worker usa el driver oficial de MongoDB con compatibilidad Node.js; su colocación inteligente reduce la latencia hacia Atlas.
