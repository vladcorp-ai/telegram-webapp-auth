import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { telegramWebAppAuth, validateLoginWidget, validateWebAppInitData, type LoginWidgetData } from '../src/index.js';

const TOKEN = '123456:TEST-token-for-unit-tests';
const NOW = 1_700_000_000;

/** Builds initData the same way Telegram does, so tests don't depend on captured real data. */
function signWebApp(fields: Record<string, string>, token = TOKEN): string {
  const check = Object.keys(fields).sort().map((k) => `${k}=${fields[k]}`).join('\n');
  const secret = createHmac('sha256', 'WebAppData').update(token).digest();
  const hash = createHmac('sha256', secret).update(check).digest('hex');
  return new URLSearchParams({ ...fields, hash }).toString();
}

function signWidget(fields: Record<string, string | number>, token = TOKEN): LoginWidgetData {
  const check = Object.keys(fields).sort().map((k) => `${k}=${fields[k]}`).join('\n');
  const secret = createHash('sha256').update(token).digest();
  return { ...fields, hash: createHmac('sha256', secret).update(check).digest('hex') } as LoginWidgetData;
}

const user = { id: 42, first_name: 'Ali', username: 'ali_dev', language_code: 'uz' };
const base = { auth_date: String(NOW - 60), query_id: 'AAE', user: JSON.stringify(user) };

describe('validateWebAppInitData', () => {
  it('accepts correctly signed data and parses the user', () => {
    const r = validateWebAppInitData(signWebApp(base), TOKEN, { now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.user).toEqual(user);
      expect(r.data.auth_date).toBe(NOW - 60);
      expect(r.data.query_id).toBe('AAE');
    }
  });

  it('rejects data signed with another bot token', () => {
    const r = validateWebAppInitData(signWebApp(base, '999:other'), TOKEN, { now: NOW });
    expect(r).toEqual({ ok: false, reason: 'bad_hash' });
  });

  it('rejects tampered fields', () => {
    const tampered = signWebApp(base).replace('ali_dev', 'admin');
    expect(validateWebAppInitData(tampered, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'bad_hash' });
  });

  it('rejects missing hash and non-hex hash', () => {
    expect(validateWebAppInitData('auth_date=1', TOKEN)).toEqual({ ok: false, reason: 'missing_hash' });
    expect(validateWebAppInitData('auth_date=1&hash=zzzz', TOKEN)).toEqual({ ok: false, reason: 'bad_hash' });
  });

  it('rejects expired data, respects maxAgeSeconds and 0 = disabled', () => {
    const old = signWebApp({ ...base, auth_date: String(NOW - 2 * 86_400) });
    expect(validateWebAppInitData(old, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'expired' });
    expect(validateWebAppInitData(old, TOKEN, { now: NOW, maxAgeSeconds: 0 }).ok).toBe(true);
    expect(validateWebAppInitData(signWebApp(base), TOKEN, { now: NOW, maxAgeSeconds: 30 }).ok).toBe(false);
  });

  it('rejects auth_date far in the future', () => {
    const future = signWebApp({ ...base, auth_date: String(NOW + 3600) });
    expect(validateWebAppInitData(future, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'expired' });
  });

  it('ignores the "signature" field when building the check string', () => {
    const signed = signWebApp(base) + '&signature=abc';
    expect(validateWebAppInitData(signed, TOKEN, { now: NOW }).ok).toBe(true);
  });

  it('reports malformed JSON in user as malformed, not as a crash', () => {
    const bad = signWebApp({ ...base, user: '{not json' });
    expect(validateWebAppInitData(bad, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('validateLoginWidget', () => {
  const widget = { id: 42, first_name: 'Ali', username: 'ali_dev', auth_date: NOW - 10 };

  it('accepts correctly signed widget data', () => {
    const r = validateLoginWidget(signWidget(widget), TOKEN, { now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data).toMatchObject({ id: 42, username: 'ali_dev', auth_date: NOW - 10 });
  });

  it('rejects widget data checked with the Mini App algorithm (keys differ)', () => {
    const asWebApp = signWebApp(Object.fromEntries(Object.entries(widget).map(([k, v]) => [k, String(v)])));
    const hash = new URLSearchParams(asWebApp).get('hash')!;
    expect(validateLoginWidget({ ...widget, hash } as LoginWidgetData, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'bad_hash' });
  });

  it('rejects tampered id', () => {
    const signed = signWidget(widget);
    expect(validateLoginWidget({ ...signed, id: 1 } as LoginWidgetData, TOKEN, { now: NOW })).toEqual({ ok: false, reason: 'bad_hash' });
  });
});

describe('telegramWebAppAuth middleware', () => {
  const mw = telegramWebAppAuth({ botToken: TOKEN, now: NOW });
  const res = () => {
    const r: any = {};
    r.status = vi.fn(() => r);
    r.json = vi.fn(() => r);
    return r;
  };

  it('puts parsed data on req.telegram and calls next()', () => {
    const req: any = { headers: { authorization: `tma ${signWebApp(base)}` } };
    const next = vi.fn();
    mw(req, res(), next);
    expect(next).toHaveBeenCalledOnce();
    expect(req.telegram.user.id).toBe(42);
  });

  it('responds 401 without the header and with an invalid signature', () => {
    const r1 = res();
    mw({ headers: {} } as any, r1, vi.fn());
    expect(r1.status).toHaveBeenCalledWith(401);
    expect(r1.json).toHaveBeenCalledWith({ error: 'missing_init_data' });

    const r2 = res();
    mw({ headers: { authorization: `tma ${signWebApp(base, '1:x')}` } } as any, r2, vi.fn());
    expect(r2.json).toHaveBeenCalledWith({ error: 'bad_hash' });
  });

  it('supports a per-request bot token (multi-bot / multi-tenant)', () => {
    const multi = telegramWebAppAuth({ botToken: (req: any) => req.headers['x-bot'], now: NOW });
    const req: any = { headers: { 'x-bot': '777:tenant', authorization: `tma ${signWebApp(base, '777:tenant')}` } };
    const next = vi.fn();
    multi(req, res(), next);
    expect(next).toHaveBeenCalledOnce();
  });
});
