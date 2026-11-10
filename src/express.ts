import type { NextFunction, Request, Response } from 'express';
import { validateWebAppInitData, type ValidateOptions, type WebAppInitData } from './index.js';

declare module 'express-serve-static-core' {
  interface Request {
    telegram?: WebAppInitData;
  }
}

export interface MiddlewareOptions extends ValidateOptions {
  /** Bot token, or a function returning it (e.g. per-tenant bots). */
  botToken: string | ((req: Request) => string);
  /** Where to read initData from. Default: `Authorization: tma <initData>` header. */
  getInitData?: (req: Request) => string | undefined;
}

const fromAuthHeader = (req: Request): string | undefined => {
  const h = req.headers.authorization;
  return h && h.startsWith('tma ') ? h.slice(4) : undefined;
};

/**
 * Express middleware: validates Mini App initData and puts the parsed result on `req.telegram`.
 * Responds 401 with `{ error: <reason> }` when validation fails.
 */
export function telegramWebAppAuth(options: MiddlewareOptions) {
  const read = options.getInitData ?? fromAuthHeader;
  return (req: Request, res: Response, next: NextFunction) => {
    const initData = read(req);
    if (!initData) return res.status(401).json({ error: 'missing_init_data' });
    const token = typeof options.botToken === 'function' ? options.botToken(req) : options.botToken;
    const result = validateWebAppInitData(initData, token, options);
    if (!result.ok) return res.status(401).json({ error: result.reason });
    req.telegram = result.data;
    next();
  };
}
