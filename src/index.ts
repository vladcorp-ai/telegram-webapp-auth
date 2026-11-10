import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** Telegram user as sent by Mini Apps (`initData.user`) and the Login Widget. */
export interface TelegramUser {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
  is_premium?: boolean;
  photo_url?: string;
  allows_write_to_pm?: boolean;
}

export interface ValidateOptions {
  /** Reject data older than this many seconds (default: 86400 = 24 h). Use 0 to disable. */
  maxAgeSeconds?: number;
  /** Current time in seconds — injectable for tests. */
  now?: number;
}

export type ValidationResult<T> =
  | { ok: true; data: T }
  | { ok: false; reason: 'missing_hash' | 'bad_hash' | 'expired' | 'malformed' };

export interface WebAppInitData {
  user?: TelegramUser;
  receiver?: TelegramUser;
  chat_instance?: string;
  chat_type?: string;
  start_param?: string;
  query_id?: string;
  auth_date: number;
  /** All raw fields (strings), including ones not modelled above. */
  raw: Record<string, string>;
}

const DAY = 86_400;

function safeEqualHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]+$/i.test(a) || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

function checkAge(authDate: number, opts: ValidateOptions): boolean {
  const maxAge = opts.maxAgeSeconds ?? DAY;
  if (maxAge === 0) return true;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  return now - authDate <= maxAge && authDate - now <= 60; // allow 60 s clock skew
}

function dataCheckString(fields: Record<string, string>): string {
  return Object.keys(fields)
    .filter((k) => k !== 'hash' && k !== 'signature')
    .sort()
    .map((k) => `${k}=${fields[k]}`)
    .join('\n');
}

function parseJson<T>(value: string | undefined): T | undefined {
  if (value === undefined) return undefined;
  return JSON.parse(value) as T;
}

/**
 * Validates `Telegram.WebApp.initData` (the raw query string) for a Mini App.
 * Algorithm: secret = HMAC_SHA256(key="WebAppData", botToken); hash = HMAC_SHA256(secret, data_check_string).
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 */
export function validateWebAppInitData(
  initData: string,
  botToken: string,
  opts: ValidateOptions = {},
): ValidationResult<WebAppInitData> {
  const params = new URLSearchParams(initData);
  const raw: Record<string, string> = {};
  for (const [k, v] of params) raw[k] = v;

  const hash = raw.hash;
  if (!hash) return { ok: false, reason: 'missing_hash' };

  const secret = createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expected = createHmac('sha256', secret).update(dataCheckString(raw)).digest('hex');
  if (!safeEqualHex(hash, expected)) return { ok: false, reason: 'bad_hash' };

  const authDate = Number(raw.auth_date);
  if (!Number.isFinite(authDate)) return { ok: false, reason: 'malformed' };
  if (!checkAge(authDate, opts)) return { ok: false, reason: 'expired' };

  try {
    return {
      ok: true,
      data: {
        user: parseJson<TelegramUser>(raw.user),
        receiver: parseJson<TelegramUser>(raw.receiver),
        chat_instance: raw.chat_instance,
        chat_type: raw.chat_type,
        start_param: raw.start_param,
        query_id: raw.query_id,
        auth_date: authDate,
        raw,
      },
    };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

/** Fields sent by the Telegram Login Widget (all values as received). */
export type LoginWidgetData = Record<string, string | number> & { hash: string; auth_date: string | number; id: string | number };

/**
 * Validates data from the Telegram Login Widget.
 * Algorithm: secret = SHA256(botToken); hash = HMAC_SHA256(secret, data_check_string).
 * https://core.telegram.org/widgets/login#checking-authorization
 */
export function validateLoginWidget(
  data: LoginWidgetData,
  botToken: string,
  opts: ValidateOptions = {},
): ValidationResult<TelegramUser & { auth_date: number }> {
  if (!data || !data.hash) return { ok: false, reason: 'missing_hash' };
  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(data)) if (v !== undefined && v !== null) fields[k] = String(v);

  const secret = createHash('sha256').update(botToken).digest();
  const expected = createHmac('sha256', secret).update(dataCheckString(fields)).digest('hex');
  if (!safeEqualHex(String(data.hash), expected)) return { ok: false, reason: 'bad_hash' };

  const authDate = Number(fields.auth_date);
  const id = Number(fields.id);
  if (!Number.isFinite(authDate) || !Number.isFinite(id)) return { ok: false, reason: 'malformed' };
  if (!checkAge(authDate, opts)) return { ok: false, reason: 'expired' };

  return {
    ok: true,
    data: {
      id,
      first_name: fields.first_name ?? '',
      last_name: fields.last_name,
      username: fields.username,
      photo_url: fields.photo_url,
      auth_date: authDate,
    },
  };
}

export { telegramWebAppAuth } from './express.js';
