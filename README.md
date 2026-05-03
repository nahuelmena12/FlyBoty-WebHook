# FlyBoty Mercado Pago Webhook

Webhook de Mercado Pago preparado para produccion con:

- validacion de firma
- persistencia en MongoDB
- actualizacion de la coleccion `schools`
- rate limiting
- headers de seguridad con `helmet`
- soporte para proxy reverso con `nginx`

## Variables de entorno

Copiar `.env.example` a `.env` y completar:

- `MONGODB_URI`
- `MONGODB_DB`
- `MP_ACCESS_TOKEN`
- `MP_WEBHOOK_SECRET`

## Desarrollo local

```bash
npm install
npm run dev
```

## Produccion

```bash
npm ci --omit=dev
node index.js
```

En servidor Ubuntu se recomienda ejecutar con `systemd` y publicar con `nginx`.

## Endpoint

- `POST /webhook/mercadopago`
- `GET /health`

## URL recomendada

`https://webhook.flyboty.com/webhook/mercadopago`
