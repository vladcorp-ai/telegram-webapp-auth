# telegram-webapp-auth

Zero-dependency validation of **Telegram Mini App `initData`** and **Telegram Login Widget** data for Node.js, plus a tiny **Express middleware**. Written in TypeScript, fully tested.

I use this pattern in production Telegram products ([MasterUz](https://github.com/vladcorp-ai/masteruz-showcase), [Fit Trainer](https://github.com/vladcorp-ai/fit-trainer-showcase)); this is a clean, standalone version.

## Why

Telegram signs the data it passes to your Mini App and to the Login Widget — but with **two different algorithms**. Getting it wrong (or skipping the check) lets anyone impersonate any user. This library:

- implements both algorithms exactly as documented by Telegram;
- compares hashes in **constant time**;
- rejects **expired** data (default 24 h) and timestamps from the future;
- never throws on malformed input — returns a typed `{ ok: false, reason }`;
- supports **per-request bot tokens** (several bots / multi-tenant backends).

## Usage

```ts
import { validateWebAppInitData, validateLoginWidget, telegramWebAppAuth } from 'telegram-webapp-auth';

// 1. Mini App: initData is the raw string from Telegram.WebApp.initData
const result = validateWebAppInitData(initData, process.env.BOT_TOKEN!, { maxAgeSeconds: 3600 });
if (result.ok) console.log(result.data.user?.id);
else console.warn(result.reason); // 'missing_hash' | 'bad_hash' | 'expired' | 'malformed'

// 2. Login Widget: the object you receive in the widget callback / redirect query
const login = validateLoginWidget(widgetData, process.env.BOT_TOKEN!);

// 3. Express: client sends `Authorization: tma <initData>`
app.use('/api', telegramWebAppAuth({ botToken: process.env.BOT_TOKEN! }));
app.get('/api/me', (req, res) => res.json(req.telegram!.user));
```

Client side:

```ts
fetch('/api/me', { headers: { Authorization: `tma ${Telegram.WebApp.initData}` } });
```

## How it works

| | Mini App `initData` | Login Widget |
|---|---|---|
| Secret key | `HMAC_SHA256(key = "WebAppData", data = botToken)` | `SHA256(botToken)` |
| Hash | `HMAC_SHA256(secret, data_check_string)` | `HMAC_SHA256(secret, data_check_string)` |
| `data_check_string` | all fields except `hash` / `signature`, sorted, `key=value` joined by `\n` | same |

Docs: [Mini Apps](https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app) · [Login Widget](https://core.telegram.org/widgets/login#checking-authorization)

## Development

```bash
npm install
npm test          # vitest — 14 tests: valid data, wrong token, tampering, expiry, future dates, malformed JSON, middleware
npm run typecheck
npm run build
```

Tests sign fixtures with the same algorithm Telegram uses, so no real tokens or user data are stored in the repo.

## License

MIT © Vlad (VladCorp AI)
