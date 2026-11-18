import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import {
  buildVerificationPrompt,
  computeSubAdminPool,
  isAccountExpired,
  isAllowedProxyUrl,
  maskEmailAddress,
  normalizeImageResolution,
  normalizeSupportLink,
  normalizeUserImageApiOverride,
  normalizeUserVoiceApiOverride,
  resolveEffectiveModelSettings,
  SECTOR_META,
  shouldRequireOtpForRole,
  USER_IMAGE_API_OPTIONS,
  USER_VOICE_API_OPTIONS,
  validateEmailFormat,
  validatePasswordStrength,
  validateSubAdminCreationLimits,
  validateSubAdminResetQuota,
  validateUsernameForSignup,
  type EngineReadiness,
  type ImageResolutionPreset,
  type ModelSettings,
  type OtpSettings,
  type PersistedPoseItem,
  type PersistedVideoItem,
  type PersistedVoiceItem,
  type PoseRealismProfile,
  type PublicUser,
  type SectorId,
  type StudioSessionDraft,
  type SupportChannelConfig,
  type SupportLinkKind,
  type UserImageApiOption,
  type UserVoiceApiOption,
  type VoiceCountry,
  type VoiceEmotion,
  type VoiceTranslationTarget,
} from './src/shared/studioRules.ts';
import {
  createOtpChallenge,
  getOtpChallengeMeta,
  invalidateOtpChallenge,
  isScryptHash,
  resolveSessionTtlMs,
  SESSION_COOKIE_NAME,
  signInviteToken,
  signSessionToken,
  verifyInviteToken,
  verifyOtpChallenge,
  verifyPassword,
  verifySessionToken,
} from './server/auth.ts';
import {
  checkRateLimit,
  getActiveLockouts,
  resetAccountLockouts,
  resetRateLimit,
} from './server/rateLimit.ts';
import {
  appendActivityLog,
  appendUserMediaHistory,
  atomicIncrementUsage,
  cleanupSupportOnUserDelete,
  clearUserHistoryKind,
  createUser,
  deleteSupportThread,
  deleteUserById,
  deleteUserHistoryItem,
  findMainAdmin,
  findUserByEmail,
  findUserById,
  findUserByUsername,
  findUserByUsernameOrEmail,
  getActivityLogs,
  getAllUsers,
  getStudioSettings,
  getSupportOverviewForUser,
  getUserWorkspaceSnapshot,
  initPersistentSessionSecret,
  isParentSubAdminBlocked,
  markSupportThreadRead,
  reassignChildUsers,
  refundUserQuota,
  reserveUserQuota,
  resetUserUsageById,
  revokeUserSessions,
  rotateUserInviteVersion,
  sanitizeUser,
  saveSupportChannelsForOwner,
  sendSupportMessage,
  syncUserWorkspaceData,
  updateModelSettings,
  updateOtpSettings,
  updateUserById,
} from './server/store.ts';
import {
  generateLipSyncVideo,
  generateRegionalVoice,
  generateStudioImage,
  getServerEngineReadiness,
  sendOtpEmailServerSide,
  transcribeAudioToText,
  translateStudioScript,
} from './server/aiClients.ts';

interface AuthenticatedRequest extends Request {
  authUser?: PublicUser;
}

const subAdminPoolLocks = new Map<string, Promise<void>>();

function withSubAdminPoolLock<T>(subAdminId: string, task: () => Promise<T>): Promise<T> {
  const prev = subAdminPoolLocks.get(subAdminId) || Promise.resolve();
  const next = prev.then(() => task());
  const marker = next.then(
    () => undefined,
    () => undefined
  );
  subAdminPoolLocks.set(subAdminId, marker);
  return next.finally(() => {
    if (subAdminPoolLocks.get(subAdminId) === marker) {
      subAdminPoolLocks.delete(subAdminId);
    }
  });
}

function parseFiniteQuotaInput(raw: unknown, fallback?: number): number | null {
  if (raw === undefined || raw === null || raw === '') {
    return fallback !== undefined ? Math.floor(fallback) : null;
  }
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return Math.floor(n);
}

function getClientIp(req: Request): string {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function parseDeviceLabel(uaHeader?: string | string[]): string {
  const ua = Array.isArray(uaHeader) ? uaHeader[0] : uaHeader || '';
  if (!ua) return 'Unknown Device';
  const browser = /Edg\//i.test(ua)
    ? 'Edge'
    : /Chrome\//i.test(ua) && !/Chromium/i.test(ua)
    ? 'Chrome'
    : /Firefox\//i.test(ua)
    ? 'Firefox'
    : /Safari\//i.test(ua) && !/Chrome/i.test(ua)
    ? 'Safari'
    : 'Browser';
  const os = /iPhone|iPad/i.test(ua)
    ? 'iOS'
    : /Android/i.test(ua)
    ? 'Android'
    : /Windows/i.test(ua)
    ? 'Windows'
    : /Mac OS X/i.test(ua)
    ? 'macOS'
    : /Linux/i.test(ua)
    ? 'Linux'
    : 'Desktop';
  return `${browser} / ${os}`;
}

function isRequestHttps(req: Request): boolean {
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const originOrReferer = String(req.headers.origin || req.headers.referer || '').trim().toLowerCase();
  return req.secure || proto === 'https' || originOrReferer.startsWith('https://');
}

function clearSessionCookie(req: Request, res: Response): void {
  const isHttps = isRequestHttps(req);
  res.clearCookie(SESSION_COOKIE_NAME, {
    path: '/',
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps,
  });
}

function setSessionCookie(
  req: Request,
  res: Response,
  user: PublicUser,
  tokenVersion = 1,
  ttlDays?: number
): string {
  const token = signSessionToken(user.id, user.role, tokenVersion, ttlDays);
  const isHttps = isRequestHttps(req);

  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps,
    maxAge: resolveSessionTtlMs(ttlDays),
    path: '/',
  });
  return token;
}

function resolveExpiresAt(expiresInDays?: number | null, explicitExpiresAt?: string | null): string | null {
  if (explicitExpiresAt === null) return null;
  if (typeof explicitExpiresAt === 'string' && explicitExpiresAt.trim()) {
    const parsed = Date.parse(explicitExpiresAt);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
  }
  if (typeof expiresInDays === 'number' && Number.isFinite(expiresInDays) && expiresInDays > 0) {
    return new Date(Date.now() + Math.floor(expiresInDays) * 86400 * 1000).toISOString();
  }
  return null;
}

function extractSessionToken(req: Request): string | undefined {
  const cookieToken = req.cookies?.[SESSION_COOKIE_NAME] as string | undefined;
  if (cookieToken) return cookieToken;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) return bearer;
  }
  return undefined;
}

async function getEnrichedReadiness(): Promise<EngineReadiness> {
  const base = getServerEngineReadiness();
  try {
    const { modelSettings, otpSettings } = await getStudioSettings();
    return {
      ...base,
      passwordPolicy: otpSettings.passwordPolicy || 'standard',
      maintenanceMode: Boolean(otpSettings.maintenanceMode),
      maintenanceMessage: otpSettings.maintenanceMessage || '',
      globalNotice: otpSettings.globalNotice || '',
      deepinfraImageResolution: normalizeImageResolution(modelSettings.deepinfraImageResolution),
    };
  } catch {
    return base;
  }
}

async function resolveUserGenerationSettings(
  user: PublicUser,
  globalSettings: ModelSettings
): Promise<{
  effectiveSettings: ModelSettings;
  strictImageEngine: boolean;
  strictVoiceEngine: boolean;
}> {
  let freshUser: PublicUser = user;
  try {
    const latest = await findUserById(user.id);
    if (latest) freshUser = latest;
  } catch {
    // keep authUser fallback
  }
  let parentSubAdmin: PublicUser | null = null;
  if (freshUser.role === 'user' && freshUser.createdBy && freshUser.createdBy !== 'system') {
    try {
      const parent = await findUserByUsername(freshUser.createdBy);
      if (parent && parent.role === 'subadmin') {
        parentSubAdmin = parent;
      }
    } catch {
      // ignore lookup error
    }
  }
  return resolveEffectiveModelSettings(globalSettings, freshUser, parentSubAdmin);
}

function formatGenerationErrorForClient(
  err: unknown,
  role: PublicUser['role'],
  fallbackMsg: string
): string {
  const msg = err instanceof Error ? err.message : fallbackMsg;
  if (role === 'main_admin') return msg;
  if (
    /GEMINI_API_KEY|DEEPINFRA_API_KEY|FAL_API_KEY|ELEVENLABS_API_KEY|TOGETHER_API_KEY|HUGGINGFACE_API_KEY|REPLICATE_API_TOKEN|CLOUDFLARE_API_TOKEN|CLOUDFLARE_ACCOUNT_ID|GROQ_API_KEY|OPENROUTER_API_KEY|Authentication Error|বিলিং সমস্যা|Rate Limit|সার্ভারে লোড হচ্ছে|নির্বাচিত মডেলটি ইমেজ আউটপুট|সার্ভারে|সেট করা নেই|সময়সীমা অতিক্রম|Timeout|Paid Plan প্রয়োজন/i.test(
      msg
    )
  ) {
    return msg;
  }
  return fallbackMsg;
}

type AsyncExpressHandler = (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void> | void;

function asyncRoute(fn: AsyncExpressHandler) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function requireCsrfOrBearer(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    next();
    return;
  }
  const hasCustomHeader = req.headers['x-vvs-client'] === '1';
  const hasBearer = Boolean(req.headers.authorization && req.headers.authorization.startsWith('Bearer '));
  if (hasCustomHeader || hasBearer) {
    next();
    return;
  }
  const host = (req.get('host') || '').toLowerCase();
  const originHeader = req.get('origin') || req.get('referer') || '';
  if (originHeader && host) {
    try {
      const parsed = new URL(originHeader);
      if (parsed.host.toLowerCase() === host) {
        next();
        return;
      }
    } catch {
      // fall through
    }
  }
  res.status(403).json({
    error: 'নিরাপত্তা যাচাইকরণ ব্যর্থ (CSRF Guard)। অনুগ্রহ করে পেজ রিফ্রেশ করে আবার চেষ্টা করুন।',
  });
}

async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const token = extractSessionToken(req);
    const session = verifySessionToken(token);
    if (!session) {
      res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন।' });
      return;
    }
    const user = await findUserById(session.userId);
    if (!user) {
      clearSessionCookie(req, res);
      res.status(401).json({ error: 'সেশন পাওয়া যায়নি। আবার লগইন করুন।' });
      return;
    }
    const currentTv = user.tokenVersion || 1;
    if ((session.tv ?? 1) !== currentTv) {
      clearSessionCookie(req, res);
      res.status(401).json({ error: 'সেশনটির মেয়াদ শেষ বা অন্য ডিভাইস থেকে বাতিল করা হয়েছে। আবার লগইন করুন।' });
      return;
    }
    if (user.role !== 'main_admin') {
      if (user.approvalStatus === 'pending') {
        clearSessionCookie(req, res);
        res.status(403).json({
          error: 'আপনার অ্যাকাউন্টটি এখনো অ্যাডমিন/সাব-অ্যাডমিন একসেপ্ট করেননি। অনুমোদন পাওয়ার পর লগইন ও ব্যবহার করতে পারবেন।',
        });
        return;
      }
      if (user.isActive === false) {
        clearSessionCookie(req, res);
        res.status(403).json({ error: 'আপনার অ্যাকাউন্টটি সাময়িকভাবে সাসপেন্ড করা হয়েছে।' });
        return;
      }
      if (isAccountExpired(user.expiresAt)) {
        clearSessionCookie(req, res);
        res.status(403).json({ error: 'আপনার অ্যাকাউন্টের মেয়াদ শেষ হয়ে গেছে।' });
        return;
      }
      const parentCheck = await isParentSubAdminBlocked(user, false);
      if (parentCheck.blocked) {
        clearSessionCookie(req, res);
        res.status(403).json({ error: parentCheck.reason || 'অ্যাকাউন্ট সাময়িকভাবে বন্ধ রয়েছে।' });
        return;
      }
    }
    req.authUser = sanitizeUser(user);
    next();
  } catch (err) {
    next(err);
  }
}

async function startServer() {
  await initPersistentSessionSecret();

  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=()');
    next();
  });
  app.use(express.json({ limit: '25mb' }));
  app.use(cookieParser());
  app.use('/api', requireCsrfOrBearer);

  // Healthcheck
  app.get('/api/health', asyncRoute(async (_req, res) => {
    res.json({ ok: true, readiness: await getEnrichedReadiness() });
  }));

  // Current Session & Engine Readiness
  app.get('/api/auth/me', asyncRoute(async (req, res) => {
    const readiness = await getEnrichedReadiness();
    const token = extractSessionToken(req);
    const session = verifySessionToken(token);
    if (!session) {
      res.json({ user: null, readiness });
      return;
    }
    const found = await findUserById(session.userId);
    if (
      !found ||
      (session.tv ?? 1) !== (found.tokenVersion || 1) ||
      (found.role !== 'main_admin' &&
        (found.approvalStatus === 'pending' || found.isActive === false || isAccountExpired(found.expiresAt)))
    ) {
      clearSessionCookie(req, res);
      res.json({ user: null, readiness });
      return;
    }
    if (found.role === 'user') {
      const parentCheck = await isParentSubAdminBlocked(found, false);
      if (parentCheck.blocked) {
        clearSessionCookie(req, res);
        res.json({ user: null, readiness });
        return;
      }
    }
    res.json({
      user: sanitizeUser(found),
      readiness,
    });
  }));

  // Login (IP + Account rate limited; strict email + status/expiry + scrypt + role-based OTP)
  app.post('/api/auth/login', asyncRoute(async (req, res) => {
    const { username, email, password } = req.body as {
      username?: string;
      email?: string;
      password?: string;
    };
    if (!username || !email || !password) {
      res.status(400).json({ error: 'ইউজারনেম, ইমেইল এবং পাসওয়ার্ড সবগুলো দিন।' });
      return;
    }

    const { otpSettings } = await getStudioSettings();
    const maxFailed = Math.min(20, Math.max(5, otpSettings.maxFailedLogins ?? 8));
    const normUser = username.trim().toLowerCase();
    const ip = getClientIp(req);
    const deviceLabel = parseDeviceLabel(req.headers['user-agent']);
    const rateKey = `${ip}:${normUser}`;
    const rlIp = checkRateLimit('login', rateKey, maxFailed + 2, 10 * 60 * 1000);
    const rlAccount = checkRateLimit('login_acct', normUser, maxFailed, 15 * 60 * 1000);
    if (!rlIp.allowed || !rlAccount.allowed) {
      const waitSec = Math.max(rlIp.retryAfterSec, rlAccount.retryAfterSec);
      await appendActivityLog({
        actor: username.trim().slice(0, 40),
        role: 'user',
        action: 'ব্রুট-ফোর্স লকআউট',
        detail: `${deviceLabel} · IP: ${ip} (${waitSec}s)`,
        status: 'error',
      }).catch(() => {});
      res.status(429).json({
        error: `অতিরিক্ত ভুল লগইন চেষ্টার কারণে অ্যাকাউন্টটি সাময়িকভাবে লক করা হয়েছে। ${waitSec} সেকেন্ড পর চেষ্টা করুন।`,
      });
      return;
    }

    const userRecord = await findUserByUsername(username);
    const emailMatch =
      Boolean(userRecord?.email) &&
      userRecord!.email.trim().toLowerCase() === email.trim().toLowerCase();
    if (!userRecord || !emailMatch || !verifyPassword(password.trim(), userRecord.passwordHash)) {
      await appendActivityLog({
        actor: username.trim().slice(0, 40),
        role: userRecord?.role || 'user',
        action: 'লগইন ব্যর্থ',
        detail: `${deviceLabel} · IP: ${ip}`,
        status: 'warning',
      }).catch(() => {});
      res.status(401).json({ error: 'ইউজারনেম, ইমেইল অথবা পাসওয়ার্ড সঠিক নয়!' });
      return;
    }

    if (userRecord.role !== 'main_admin') {
      if (userRecord.approvalStatus === 'pending') {
        res.status(403).json({
          error: `আপনার অ্যাকাউন্টটি এখনো অনুমোদিত হয়নি। "${userRecord.createdBy}"-এর প্যানেল থেকে একসেপ্ট করার পর লগইন করতে পারবেন।`,
        });
        return;
      }
      if (userRecord.isActive === false) {
        res.status(403).json({ error: 'আপনার অ্যাকাউন্টটি সাময়িকভাবে সাসপেন্ড (ব্লক) করা হয়েছে। অ্যাডমিনের সাথে যোগাযোগ করুন।' });
        return;
      }
      if (isAccountExpired(userRecord.expiresAt)) {
        res.status(403).json({ error: 'আপনার অ্যাকাউন্টের মেয়াদ শেষ হয়ে গেছে। অ্যাডমিনের সাথে যোগাযোগ করুন।' });
        return;
      }
      const parentCheck = await isParentSubAdminBlocked(userRecord, false);
      if (parentCheck.blocked) {
        res.status(403).json({ error: parentCheck.reason || 'সাব-অ্যাডমিন সাসপেন্ড রয়েছে।' });
        return;
      }
    }

    resetRateLimit('login', rateKey);
    resetRateLimit('login_acct', normUser);

    let effectiveTv = userRecord.tokenVersion || 1;
    if (!isScryptHash(userRecord.passwordHash)) {
      const migrated = await updateUserById(userRecord.id, { password: password.trim() }).catch(() => null);
      if (migrated && migrated.ok) effectiveTv = migrated.tokenVersion;
    }

    const readiness = await getEnrichedReadiness();

    if (shouldRequireOtpForRole(userRecord.role, otpSettings) && readiness.otpEmailConfigured) {
      const targetEmail = userRecord.email || email.trim().toLowerCase();
      const { challengeId, code } = createOtpChallenge(userRecord.id, targetEmail, 'login');
      const mailRes = await sendOtpEmailServerSide(
        targetEmail,
        userRecord.username,
        code,
        'Login Verification'
      );
      if (!mailRes.sent) {
        res.status(502).json({
          error: `OTP ইমেইল পাঠানো যায়নি (${mailRes.detail || 'Mailer error'})। অ্যাডমিনকে জানান।`,
        });
        return;
      }
      await appendActivityLog({
        actor: userRecord.username,
        role: userRecord.role,
        action: 'লগইন OTP পাঠানো হয়েছে',
        detail: `${maskEmailAddress(targetEmail)} · ${deviceLabel}`,
        status: 'success',
      }).catch(() => {});
      res.json({
        otpRequired: true,
        challengeId,
        maskedEmail: maskEmailAddress(targetEmail),
      });
      return;
    }

    const safeUser = sanitizeUser(userRecord);
    const sessionToken = setSessionCookie(req, res, safeUser, effectiveTv, otpSettings.sessionTtlDays);
    await appendActivityLog({
      actor: safeUser.username,
      role: safeUser.role,
      action: 'সফল লগইন',
      detail: `${deviceLabel} · IP: ${ip}`,
      status: 'success',
    }).catch(() => {});
    res.json({ otpRequired: false, user: safeUser, readiness, sessionToken });
  }));

  app.post('/api/auth/verify-otp', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const deviceLabel = parseDeviceLabel(req.headers['user-agent']);
    const rl = checkRateLimit('otp_verify', ip, 10, 10 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অতিরিক্ত চেষ্টা! ${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }

    const { challengeId, code } = req.body as { challengeId?: string; code?: string };
    if (!challengeId || !code) {
      res.status(400).json({ error: 'OTP কোড দিন।' });
      return;
    }
    const check = verifyOtpChallenge(challengeId, code, 'login');
    if (!check.ok) {
      res.status(401).json({ error: check.message });
      return;
    }
    const found = await findUserById(check.userId);
    if (!found) {
      res.status(404).json({ error: 'ইউজার পাওয়া যায়নি।' });
      return;
    }
    if (found.role !== 'main_admin' && found.approvalStatus === 'pending') {
      res.status(403).json({
        error: 'আপনার অ্যাকাউন্টটি এখনো একসেপ্ট করা হয়নি। অনুমোদনের পর লগইন করুন।',
      });
      return;
    }
    if (found.role !== 'main_admin' && (found.isActive === false || isAccountExpired(found.expiresAt))) {
      res.status(403).json({ error: 'অ্যাকাউন্ট সাসপেন্ড বা মেয়াদোত্তীর্ণ।' });
      return;
    }
    if (found.role === 'user') {
      const parentCheck = await isParentSubAdminBlocked(found, false);
      if (parentCheck.blocked) {
        res.status(403).json({ error: parentCheck.reason || 'সাব-অ্যাডমিন সাসপেন্ড রয়েছে।' });
        return;
      }
    }
    const { otpSettings } = await getStudioSettings();
    const safeUser = sanitizeUser(found);
    const sessionToken = setSessionCookie(req, res, safeUser, found.tokenVersion || 1, otpSettings.sessionTtlDays);
    await appendActivityLog({
      actor: safeUser.username,
      role: safeUser.role,
      action: 'OTP লগইন সম্পন্ন',
      detail: `${deviceLabel} · IP: ${ip}`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: safeUser, readiness: await getEnrichedReadiness(), sessionToken });
  }));

  app.post('/api/auth/resend-otp', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('otp_send', ip, 3, 3 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অনুগ্রহ করে ${rl.retryAfterSec} সেকেন্ড পর নতুন OTP চান।` });
      return;
    }

    const { challengeId } = req.body as { challengeId?: string };
    const meta = challengeId ? getOtpChallengeMeta(challengeId) : null;
    if (!meta || !challengeId) {
      res.status(400).json({ error: 'আগে লগইন তথ্য দিয়ে নতুন সেশন শুরু করুন।' });
      return;
    }
    const rlTarget = checkRateLimit('otp_target', meta.userId, 3, 5 * 60 * 1000);
    if (!rlTarget.allowed) {
      res.status(429).json({
        error: `এই অ্যাকাউন্টে সম্প্রতি OTP পাঠানো হয়েছে। ${rlTarget.retryAfterSec} সেকেন্ড অপেক্ষা করুন।`,
      });
      return;
    }
    const userRecord = await findUserById(meta.userId);
    if (!userRecord) {
      res.status(404).json({ error: 'ইউজার পাওয়া যায়নি।' });
      return;
    }
    invalidateOtpChallenge(challengeId);
    const { challengeId: newChallengeId, code } = createOtpChallenge(
      userRecord.id,
      meta.email,
      meta.purpose
    );
    const purposeLabel =
      meta.purpose === 'account_recovery'
        ? 'Account Password Recovery'
        : meta.purpose === 'admin_recovery'
        ? 'Main Admin Password Recovery'
        : 'Login Verification';
    const mailRes = await sendOtpEmailServerSide(meta.email, userRecord.username, code, purposeLabel);
    if (!mailRes.sent) {
      res.status(502).json({ error: 'নতুন OTP পাঠানো যায়নি।' });
      return;
    }
    res.json({ challengeId: newChallengeId });
  }));

  app.post('/api/auth/recovery/lookup', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('recovery_lookup', ip, 20, 5 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: 'অনুগ্রহ করে কিছুক্ষণ পর চেষ্টা করুন।' });
      return;
    }
    res.json({ found: false });
  }));

  app.post('/api/auth/recovery/request', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const { identifier } = req.body as { identifier?: string };
    const clean = (identifier || '').trim();
    if (!clean) {
      res.status(400).json({ error: 'অনুগ্রহ করে আপনার ইউজারনেম অথবা ইমেইল দিন।' });
      return;
    }

    const rlIp = checkRateLimit('otp_send', ip, 3, 3 * 60 * 1000);
    if (!rlIp.allowed) {
      res.status(429).json({ error: `OTP স্প্যাম সুরক্ষার জন্য ${rlIp.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }

    const target = await findUserByUsernameOrEmail(clean);
    if (!target) {
      res.status(404).json({ error: 'এই ইউজারনেম বা ইমেইলের কোনো অ্যাকাউন্ট পাওয়া যায়নি।' });
      return;
    }

    const rlTarget = checkRateLimit('otp_target', target.id, 3, 5 * 60 * 1000);
    if (!rlTarget.allowed) {
      res.status(429).json({ error: `এই অ্যাকাউন্টে সম্প্রতি OTP পাঠানো হয়েছে। ${rlTarget.retryAfterSec} সেকেন্ড অপেক্ষা করুন।` });
      return;
    }

    const { otpSettings } = await getStudioSettings();
    const targetEmail =
      target.role === 'main_admin' ? otpSettings.adminRecoveryEmail || target.email : target.email;
    if (!targetEmail) {
      res.status(400).json({ error: 'এই অ্যাকাউন্টে কোনো ইমেইল যুক্ত নেই। আপনার অ্যাডমিনের সাথে যোগাযোগ করুন।' });
      return;
    }
    const readiness = getServerEngineReadiness();
    if (!readiness.otpEmailConfigured) {
      res.status(400).json({
        error: 'সার্ভারে GAS_OTP_URL সেট করা নেই। রিকভারি ইমেইল পাঠাতে Secrets-এ GAS_OTP_URL যুক্ত করুন।',
      });
      return;
    }
    const { challengeId, code } = createOtpChallenge(target.id, targetEmail, 'account_recovery');
    const purposeLabel =
      target.role === 'main_admin'
        ? 'Main Admin Password Recovery'
        : target.role === 'subadmin'
        ? 'Sub-Admin Password Recovery'
        : 'User Password Recovery';
    const mailRes = await sendOtpEmailServerSide(targetEmail, target.username, code, purposeLabel);
    if (!mailRes.sent) {
      res.status(502).json({ error: 'রিকভারি ইমেইল পাঠানো যায়নি।' });
      return;
    }
    await appendActivityLog({
      actor: target.username,
      role: target.role,
      action: 'পাসওয়ার্ড রিকভারি OTP',
      detail: `${maskEmailAddress(targetEmail)} · ${parseDeviceLabel(req.headers['user-agent'])}`,
      status: 'warning',
    }).catch(() => {});
    res.json({
      challengeId,
      maskedEmail: maskEmailAddress(targetEmail),
      role: target.role,
      username: target.username,
    });
  }));

  app.post('/api/auth/recovery/confirm', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('otp_verify', ip, 10, 10 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অতিরিক্ত চেষ্টা! ${rl.retryAfterSec} সেকেন্ড পর চেষ্টা করুন।` });
      return;
    }

    const { challengeId, code, newUsername, newPassword } = req.body as {
      challengeId?: string;
      code?: string;
      newUsername?: string;
      newPassword?: string;
    };
    if (!challengeId || !code || !newPassword?.trim()) {
      res.status(400).json({ error: 'সঠিক OTP কোড এবং নতুন পাসওয়ার্ড দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(newPassword, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message });
      return;
    }
    const check = verifyOtpChallenge(challengeId, code, 'account_recovery');
    if (!check.ok) {
      res.status(401).json({ error: check.message });
      return;
    }
    const target = await findUserById(check.userId);
    if (!target) {
      res.status(404).json({ error: 'অ্যাকাউন্ট পাওয়া যায়নি।' });
      return;
    }
    const patch: { password: string; username?: string } = {
      password: newPassword.trim(),
    };
    if (target.role === 'main_admin' && newUsername?.trim()) {
      patch.username = newUsername.trim();
    }
    const updated = await updateUserById(check.userId, patch);
    if (!updated.ok) {
      res.status(400).json({ error: updated.message });
      return;
    }
    const sessionToken = setSessionCookie(req, res, updated.user, updated.tokenVersion, otpSettings.sessionTtlDays);
    await appendActivityLog({
      actor: updated.user.username,
      role: updated.user.role,
      action: 'OTP দিয়ে পাসওয়ার্ড রিসেট',
      detail: `${parseDeviceLabel(req.headers['user-agent'])} · IP: ${ip}`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: updated.user, readiness: await getEnrichedReadiness(), sessionToken });
  }));

  app.post('/api/auth/admin-recovery/request', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('otp_send', ip, 3, 3 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }
    const admin = await findMainAdmin();
    const rlTarget = checkRateLimit('otp_target', admin.id, 3, 5 * 60 * 1000);
    if (!rlTarget.allowed) {
      res.status(429).json({ error: `সম্প্রতি OTP পাঠানো হয়েছে। ${rlTarget.retryAfterSec} সেকেন্ড অপেক্ষা করুন।` });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const readiness = getServerEngineReadiness();
    if (!readiness.otpEmailConfigured) {
      res.status(400).json({
        error: 'সার্ভারে GAS_OTP_URL সেট করা নেই। রিকভারি ইমেইল পাঠাতে Secrets-এ GAS_OTP_URL যুক্ত করুন।',
      });
      return;
    }
    const targetEmail = otpSettings.adminRecoveryEmail || admin.email;
    const { challengeId, code } = createOtpChallenge(admin.id, targetEmail, 'admin_recovery');
    const mailRes = await sendOtpEmailServerSide(
      targetEmail,
      admin.username,
      code,
      'Main Admin Password Recovery'
    );
    if (!mailRes.sent) {
      res.status(502).json({ error: 'রিকভারি ইমেইল পাঠানো যায়নি।' });
      return;
    }
    res.json({
      challengeId,
      maskedEmail: maskEmailAddress(targetEmail),
    });
  }));

  app.post('/api/auth/admin-recovery/confirm', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('otp_verify', ip, 10, 10 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অতিরিক্ত চেষ্টা! ${rl.retryAfterSec} সেকেন্ড পর চেষ্টা করুন।` });
      return;
    }
    const { challengeId, code, newUsername, newPassword } = req.body as {
      challengeId?: string;
      code?: string;
      newUsername?: string;
      newPassword?: string;
    };
    if (!challengeId || !code || !newUsername?.trim() || !newPassword?.trim()) {
      res.status(400).json({ error: 'সঠিক OTP কোড, নতুন ইউজারনেম এবং পাসওয়ার্ড দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(newPassword, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message });
      return;
    }
    const check = verifyOtpChallenge(challengeId, code, 'admin_recovery');
    if (!check.ok) {
      res.status(401).json({ error: check.message });
      return;
    }
    const updated = await updateUserById(check.userId, {
      username: newUsername.trim(),
      password: newPassword.trim(),
    });
    if (!updated.ok) {
      res.status(400).json({ error: updated.message });
      return;
    }
    const sessionToken = setSessionCookie(req, res, updated.user, updated.tokenVersion, otpSettings.sessionTtlDays);
    res.json({ user: updated.user, readiness: await getEnrichedReadiness(), sessionToken });
  }));

  app.post('/api/auth/change-password', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const { currentPassword, newPassword } = req.body as {
      currentPassword?: string;
      newPassword?: string;
    };
    if (!currentPassword?.trim() || !newPassword?.trim()) {
      res.status(400).json({ error: 'বর্তমান পাসওয়ার্ড এবং নতুন পাসওয়ার্ড দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(newPassword, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message });
      return;
    }
    const record = await findUserById(req.authUser!.id);
    if (!record || !verifyPassword(currentPassword.trim(), record.passwordHash)) {
      res.status(401).json({ error: 'বর্তমান পাসওয়ার্ডটি সঠিক নয়।' });
      return;
    }
    const updated = await updateUserById(record.id, { password: newPassword.trim() });
    if (!updated.ok) {
      res.status(400).json({ error: updated.message });
      return;
    }
    const sessionToken = setSessionCookie(req, res, updated.user, updated.tokenVersion, otpSettings.sessionTtlDays);
    await appendActivityLog({
      actor: updated.user.username,
      role: updated.user.role,
      action: 'পাসওয়ার্ড পরিবর্তন',
      detail: `${parseDeviceLabel(req.headers['user-agent'])} · অন্যান্য সেশন বাতিল`,
      status: 'success',
    }).catch(() => {});
    res.json({ ok: true, user: updated.user, sessionToken });
  }));

  app.post('/api/auth/logout-all', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    await revokeUserSessions(user.id);
    clearSessionCookie(req, res);
    await appendActivityLog({
      actor: user.username,
      role: user.role,
      action: 'সব ডিভাইস থেকে লগআউট',
      detail: `${parseDeviceLabel(req.headers['user-agent'])} · সব সেশন টোকেন বাতিল`,
      status: 'warning',
    }).catch(() => {});
    res.json({ ok: true });
  }));

  app.get('/api/auth/my-activity', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const logs = await getActivityLogs();
    const myLogs = logs
      .filter((entry) => entry.actor.toLowerCase() === req.authUser!.username.toLowerCase())
      .slice(0, 20);
    res.json({ logs: myLogs });
  }));

  app.post('/api/auth/logout', (req, res) => {
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Public Invite Link Inspection & Self-Signup (Pending until Inviter Accepts)
  app.get('/api/auth/invite-info', asyncRoute(async (req, res) => {
    const token = String(req.query.token || '').trim();
    const payload = verifyInviteToken(token);
    if (!payload) {
      res.status(400).json({ error: 'ইনভাইট লিংকটি সঠিক নয় বা নষ্ট হয়ে গেছে।' });
      return;
    }
    const inviter = await findUserById(payload.inviterId);
    if (
      !inviter ||
      inviter.role !== payload.inviterRole ||
      (inviter.inviteVersion || 1) !== payload.v ||
      (inviter.role !== 'main_admin' && (inviter.isActive === false || isAccountExpired(inviter.expiresAt)))
    ) {
      res.status(400).json({ error: 'এই ইনভাইট লিংকটি নিষ্ক্রিয়, রিসেট করা হয়েছে বা মেয়াদ শেষ হয়েছে।' });
      return;
    }
    res.json({
      valid: true,
      inviterUsername: inviter.username,
      inviterRole: inviter.role,
    });
  }));

  app.post('/api/auth/register-invite', asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const rl = checkRateLimit('invite_signup', ip, 10, 15 * 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({
        error: `অতিরিক্ত সাইন-আপ অনুরোধ পাঠানো হয়েছে। ${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।`,
      });
      return;
    }

    const { token, username, email, password } = req.body as {
      token?: string;
      username?: string;
      email?: string;
      password?: string;
    };
    const payload = verifyInviteToken(token);
    if (!payload) {
      res.status(400).json({ error: 'ইনভাইট লিংকটি সঠিক নয় বা রিসেট করা হয়েছে।' });
      return;
    }
    const inviter = await findUserById(payload.inviterId);
    if (
      !inviter ||
      inviter.role !== payload.inviterRole ||
      (inviter.inviteVersion || 1) !== payload.v ||
      (inviter.role !== 'main_admin' && (inviter.isActive === false || isAccountExpired(inviter.expiresAt)))
    ) {
      res.status(400).json({ error: 'এই ইনভাইট লিংকটি বর্তমানে সক্রিয় নয়। নতুন লিংক চান।' });
      return;
    }

    if (!username || !email || !password) {
      res.status(400).json({ error: 'ইউজারনেম, ইমেইল এবং পাসওয়ার্ড সবগুলো দিন।' });
      return;
    }
    const userCheck = validateUsernameForSignup(username);
    if (!userCheck.valid) {
      res.status(400).json({ error: userCheck.message || 'সঠিক ইউজারনেম দিন।' });
      return;
    }
    if (!validateEmailFormat(email)) {
      res.status(400).json({ error: 'সঠিক ইমেইল অ্যাড্রেস দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(password, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message || 'পাসওয়ার্ড নীতিমালা পূরণ হয়নি।' });
      return;
    }

    const existingEmail = await findUserByEmail(email);
    if (existingEmail) {
      res.status(400).json({ error: 'এই ইমেইল দিয়ে ইতিমধ্যেই একটি অ্যাকাউন্ট রয়েছে!' });
      return;
    }

    const created = await createUser({
      username: username.trim(),
      email: email.trim().toLowerCase(),
      password: password.trim(),
      role: 'user',
      createdBy: inviter.username,
      picLimit: 0,
      voiceLimit: 0,
      videoLimit: 0,
      allowMasterApi: inviter.role === 'subadmin' ? inviter.allowMasterApi : true,
      isActive: true,
      approvalStatus: 'pending',
      expiresAt: null,
    });
    if (!created.ok) {
      res.status(400).json({ error: created.message });
      return;
    }

    await appendActivityLog({
      actor: created.user.username,
      role: 'user',
      action: 'ইনভাইট লিংকে অ্যাকাউন্ট আবেদন',
      detail: `আমন্ত্রণকারী: ${inviter.username} (${inviter.role === 'main_admin' ? 'Main Admin' : 'Sub-Admin'}) · অপেক্ষমাণ`,
      status: 'warning',
    }).catch(() => {});

    res.status(201).json({
      ok: true,
      pending: true,
      username: created.user.username,
      inviterUsername: inviter.username,
      inviterRole: inviter.role,
    });
  }));

  // ==========================================
  // MAIN ADMIN ROUTES
  // ==========================================
  app.get('/api/admin/overview', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'শুধুমাত্র মেইন অ্যাডমিন অ্যাক্সেস করতে পারবেন।' });
      return;
    }
    const [users, { modelSettings, otpSettings }, logs, readiness, adminRecord] = await Promise.all([
      getAllUsers(),
      getStudioSettings(),
      getActivityLogs(),
      getEnrichedReadiness(),
      findUserById(req.authUser.id),
    ]);
    const inviteToken = signInviteToken({
      inviterId: adminRecord?.id || req.authUser.id,
      inviterRole: 'main_admin',
      v: adminRecord?.inviteVersion || 1,
    });
    res.json({
      users,
      modelSettings,
      otpSettings,
      logs,
      lockouts: getActiveLockouts(),
      readiness,
      inviteToken,
    });
  }));

  app.post('/api/admin/invite-link/reset', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const nextV = await rotateUserInviteVersion(req.authUser.id);
    if (!nextV) {
      res.status(400).json({ error: 'ইনভাইট লিংক রিসেট করা যায়নি।' });
      return;
    }
    const inviteToken = signInviteToken({
      inviterId: req.authUser.id,
      inviterRole: 'main_admin',
      v: nextV,
    });
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'মেইন অ্যাডমিন ইনভাইট লিংক রিসেট',
      detail: `ভার্সন #${nextV}`,
      status: 'warning',
    }).catch(() => {});
    res.json({ inviteToken });
  }));

  app.post('/api/admin/users/:id/approve', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const target = await findUserById(String(req.params.id));
    if (!target || target.role === 'main_admin') {
      res.status(404).json({ error: 'অ্যাকাউন্ট পাওয়া যায়নি।' });
      return;
    }
    if (target.approvalStatus !== 'pending') {
      res.status(400).json({ error: 'এই অ্যাকাউন্টটি ইতিমধ্যেই অনুমোদিত রয়েছে।' });
      return;
    }
    if (target.createdBy.toLowerCase() !== req.authUser.username.toLowerCase()) {
      res.status(403).json({
        error: `এই আবেদনটি সাব-অ্যাডমিন "${target.createdBy}"-এর ইনভাইট লিংক থেকে এসেছে — তার প্যানেল থেকে একসেপ্ট করতে হবে।`,
      });
      return;
    }

    const {
      role,
      picLimit,
      voiceLimit,
      videoLimit,
      allowMasterApi,
      expiresInDays,
      imageApiOverride,
      voiceApiOverride,
    } = req.body as {
      role?: 'user' | 'subadmin';
      picLimit?: number;
      voiceLimit?: number;
      videoLimit?: number;
      allowMasterApi?: boolean;
      expiresInDays?: number | null;
      imageApiOverride?: UserImageApiOption;
      voiceApiOverride?: UserVoiceApiOption;
    };
    const nextPic = Math.floor(Number(picLimit ?? 100));
    const nextVoice = Math.floor(Number(voiceLimit ?? 30));
    const nextVideo = Math.floor(Number(videoLimit ?? 10));
    if (!Number.isFinite(nextPic) || nextPic < 1 || !Number.isFinite(nextVoice) || nextVoice < 1 || !Number.isFinite(nextVideo) || nextVideo < 0) {
      res.status(400).json({ error: 'সঠিক কোটা সংখ্যা দিন (ইমেজ ও ভয়েস কমপক্ষে ১)।' });
      return;
    }

    const updated = await updateUserById(target.id, {
      approvalStatus: 'approved',
      isActive: true,
      role: role === 'subadmin' ? 'subadmin' : 'user',
      picLimit: nextPic,
      voiceLimit: nextVoice,
      videoLimit: nextVideo,
      allowMasterApi: allowMasterApi !== false,
      expiresAt: resolveExpiresAt(expiresInDays),
      ...(imageApiOverride !== undefined
        ? { imageApiOverride: normalizeUserImageApiOverride(imageApiOverride) }
        : {}),
      ...(voiceApiOverride !== undefined
        ? { voiceApiOverride: normalizeUserVoiceApiOverride(voiceApiOverride) }
        : {}),
    });
    if (!updated.ok) {
      res.status(400).json({ error: updated.message });
      return;
    }
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'ইনভাইট আবেদন একসেপ্ট',
      detail: `${updated.user.username} (${updated.user.role} · P:${nextPic}/V:${nextVoice}/Vid:${nextVideo})`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: updated.user });
  }));

  app.get('/api/admin/lockouts', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    res.json({ lockouts: getActiveLockouts() });
  }));

  app.post('/api/admin/unlock', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const { target } = req.body as { target?: string };
    if (!target?.trim()) {
      res.status(400).json({ error: 'আনলক করার জন্য ইউজারনেম বা কী দিন।' });
      return;
    }
    const cleared = resetAccountLockouts(target);
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'লকআউট আনলক',
      detail: `${target.trim()} (${cleared}টি বাকেট রিসেট)`,
      status: 'success',
    }).catch(() => {});
    res.json({ ok: true, cleared, lockouts: getActiveLockouts() });
  }));

  app.put('/api/admin/settings', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const { modelSettings, otpSettings } = req.body as {
      modelSettings?: Partial<ModelSettings>;
      otpSettings?: Partial<OtpSettings>;
    };
    const nextModel = modelSettings ? await updateModelSettings(modelSettings) : (await getStudioSettings()).modelSettings;
    const nextOtp = otpSettings ? await updateOtpSettings(otpSettings) : (await getStudioSettings()).otpSettings;
    const readiness = await getEnrichedReadiness();
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'মডেল ও সিকিউরিটি সেটিংস আপডেট',
      detail: `Image: ${nextModel.imageEngine} (${nextModel.deepinfraImageResolution}), Text/STT: ${nextModel.textEngine}, Voice: ${nextModel.voiceEngine}, OTP: ${nextOtp.requireOtp ? 'ON' : 'OFF'}, Maint: ${nextOtp.maintenanceMode ? 'ON' : 'OFF'}`,
      status: 'success',
    }).catch(() => {});
    res.json({ modelSettings: nextModel, otpSettings: nextOtp, readiness });
  }));

  app.post('/api/admin/users', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const {
      username,
      email,
      password,
      role,
      picLimit,
      voiceLimit,
      videoLimit,
      allowMasterApi,
      isActive,
      expiresInDays,
      imageApiOverride,
      voiceApiOverride,
    } = req.body as {
      username?: string;
      email?: string;
      password?: string;
      role?: 'subadmin' | 'user';
      picLimit?: number;
      voiceLimit?: number;
      videoLimit?: number;
      allowMasterApi?: boolean;
      isActive?: boolean;
      expiresInDays?: number | null;
      imageApiOverride?: UserImageApiOption;
      voiceApiOverride?: UserVoiceApiOption;
    };
    if (!username || !email || !password) {
      res.status(400).json({ error: 'ইউজারনেম, ইমেইল এবং পাসওয়ার্ড দিন!' });
      return;
    }
    if (!validateEmailFormat(email)) {
      res.status(400).json({ error: 'সঠিক ইমেইল অ্যাড্রেস দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(password, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message });
      return;
    }
    const parsedPic = parseFiniteQuotaInput(picLimit, 100);
    const parsedVoice = parseFiniteQuotaInput(voiceLimit, 30);
    const parsedVideo = parseFiniteQuotaInput(videoLimit, 10);
    if (parsedPic === null || parsedPic < 1 || parsedVoice === null || parsedVoice < 1 || parsedVideo === null || parsedVideo < 0) {
      res.status(400).json({ error: 'ইমেজ/ভয়েস/ভিডিও লিমিটের সংখ্যা সঠিক নয়।' });
      return;
    }
    const created = await createUser({
      username,
      email,
      password,
      role: role === 'subadmin' ? 'subadmin' : 'user',
      createdBy: req.authUser.username,
      picLimit: parsedPic,
      voiceLimit: parsedVoice,
      videoLimit: parsedVideo,
      allowMasterApi: allowMasterApi !== false,
      isActive: isActive !== false,
      imageApiOverride: normalizeUserImageApiOverride(imageApiOverride),
      voiceApiOverride: normalizeUserVoiceApiOverride(voiceApiOverride),
      expiresAt: resolveExpiresAt(expiresInDays),
    });
    if (!created.ok) {
      res.status(400).json({ error: created.message });
      return;
    }
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'নতুন অ্যাকাউন্ট তৈরি',
      detail: `${created.user.username} (${created.user.role})`,
      status: 'success',
    }).catch(() => {});
    res.status(201).json({ user: created.user });
  }));

  app.patch('/api/admin/users/:id', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const body = (req.body || {}) as {
      username?: string;
      email?: string;
      password?: string;
      role?: 'subadmin' | 'user';
      picLimit?: number;
      voiceLimit?: number;
      videoLimit?: number;
      allowMasterApi?: boolean;
      isActive?: boolean;
      expiresInDays?: number | null;
      expiresAt?: string | null;
      imageApiOverride?: UserImageApiOption;
      voiceApiOverride?: UserVoiceApiOption;
    };

    if (body.email !== undefined && !validateEmailFormat(body.email)) {
      res.status(400).json({ error: 'সঠিক ইমেইল অ্যাড্রেস দিন।' });
      return;
    }
    if (
      body.imageApiOverride !== undefined &&
      !USER_IMAGE_API_OPTIONS.some((opt) => opt.value === body.imageApiOverride)
    ) {
      res.status(400).json({ error: 'অবৈধ ইমেজ API অপশন।' });
      return;
    }
    if (
      body.voiceApiOverride !== undefined &&
      !USER_VOICE_API_OPTIONS.some((opt) => opt.value === body.voiceApiOverride)
    ) {
      res.status(400).json({ error: 'অবৈধ ভয়েস API অপশন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    if (body.password && body.password.trim().length > 0) {
      const passCheck = validatePasswordStrength(body.password, otpSettings.passwordPolicy);
      if (!passCheck.valid) {
        res.status(400).json({ error: passCheck.message });
        return;
      }
    }

    const patch: Parameters<typeof updateUserById>[1] = {};
    if (body.username !== undefined) patch.username = body.username;
    if (body.email !== undefined) patch.email = body.email;
    if (body.password && body.password.trim().length > 0) patch.password = body.password;
    if (body.role === 'subadmin' || body.role === 'user') patch.role = body.role;
    if (body.picLimit !== undefined) {
      const parsed = parseFiniteQuotaInput(body.picLimit);
      if (parsed === null || parsed < 1) {
        res.status(400).json({ error: 'ইমেজ লিমিট কমপক্ষে ১ হতে হবে।' });
        return;
      }
      patch.picLimit = parsed;
    }
    if (body.voiceLimit !== undefined) {
      const parsed = parseFiniteQuotaInput(body.voiceLimit);
      if (parsed === null || parsed < 1) {
        res.status(400).json({ error: 'ভয়েস লিমিট কমপক্ষে ১ হতে হবে।' });
        return;
      }
      patch.voiceLimit = parsed;
    }
    if (body.videoLimit !== undefined) {
      const parsed = parseFiniteQuotaInput(body.videoLimit);
      if (parsed === null || parsed < 0) {
        res.status(400).json({ error: 'ভিডিও লিমিট ০ বা তার বেশি হতে হবে।' });
        return;
      }
      patch.videoLimit = parsed;
    }
    if (body.allowMasterApi !== undefined) patch.allowMasterApi = Boolean(body.allowMasterApi);
    if (body.isActive !== undefined) patch.isActive = Boolean(body.isActive);
    if (body.expiresInDays !== undefined || body.expiresAt !== undefined) {
      patch.expiresAt = resolveExpiresAt(body.expiresInDays, body.expiresAt);
    }
    if (body.imageApiOverride !== undefined) {
      patch.imageApiOverride = normalizeUserImageApiOverride(body.imageApiOverride);
    }
    if (body.voiceApiOverride !== undefined) {
      patch.voiceApiOverride = normalizeUserVoiceApiOverride(body.voiceApiOverride);
    }

    const updated = await updateUserById(String(req.params.id), patch);
    if (!updated.ok) {
      res.status(400).json({ error: updated.message });
      return;
    }
    const nextSessionToken =
      updated.user.id === req.authUser.id
        ? setSessionCookie(req, res, updated.user, updated.tokenVersion, otpSettings.sessionTtlDays)
        : undefined;
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'অ্যাকাউন্ট আপডেট',
      detail: `${updated.user.username} (${updated.user.isActive ? 'Active' : 'Suspended'} · Img:${updated.user.imageApiOverride || 'default'} / Voice:${updated.user.voiceApiOverride || 'default'})`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: updated.user, ...(nextSessionToken ? { sessionToken: nextSessionToken } : {}) });
  }));

  app.post('/api/admin/users/:id/revoke-sessions', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const target = await findUserById(String(req.params.id));
    if (!target) {
      res.status(404).json({ error: 'ইউজার পাওয়া যায়নি।' });
      return;
    }
    const nextTv = await revokeUserSessions(target.id);
    if (nextTv === null) {
      res.status(400).json({ error: 'সেশন বাতিল করা যায়নি।' });
      return;
    }
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'সেশন বাতিল (Force Logout)',
      detail: target.username,
      status: 'warning',
    }).catch(() => {});
    res.json({ ok: true });
  }));

  app.post('/api/admin/users/:id/reset-quota', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const updated = await resetUserUsageById(String(req.params.id));
    if (!updated) {
      res.status(404).json({ error: 'ইউজার পাওয়া যায়নি।' });
      return;
    }
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'কোটা রিসেট',
      detail: updated.username,
      status: 'success',
    }).catch(() => {});
    res.json({ user: updated });
  }));

  app.delete('/api/admin/users/:id', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'main_admin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const target = await findUserById(String(req.params.id));
    if (!target) {
      res.status(404).json({ error: 'ইউজার পাওয়া যায়নি।' });
      return;
    }
    let reassignedCount = 0;
    if (target.role === 'subadmin') {
      reassignedCount = await reassignChildUsers(target.username, req.authUser.username);
    }
    const ok = await deleteUserById(String(req.params.id));
    if (!ok) {
      res.status(400).json({ error: 'ডিলিট করা যায়নি।' });
      return;
    }
    await cleanupSupportOnUserDelete(target.id, target.role === 'subadmin' ? req.authUser : null).catch(() => {});
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'main_admin',
      action: 'অ্যাকাউন্ট ডিলিট',
      detail: reassignedCount > 0
        ? `${target.username} (${reassignedCount} জন ইউজার মেইন অ্যাডমিনে স্থানান্তরিত)`
        : target.username,
      status: 'warning',
    }).catch(() => {});
    res.json({ ok: true });
  }));

  // ==========================================
  // SUB-ADMIN ROUTES (With Strict Pool Accounting & Scoped Invite Approvals)
  // ==========================================
  app.get('/api/subadmin/users', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'শুধুমাত্র সাব-অ্যাডমিনের জন্য।' });
      return;
    }
    const [all, subRecord, { modelSettings }, readiness] = await Promise.all([
      getAllUsers(),
      findUserById(req.authUser.id),
      getStudioSettings(),
      getEnrichedReadiness(),
    ]);
    const activeSub = subRecord ? sanitizeUser(subRecord) : req.authUser;
    const mine = all.filter(
      (u) => u.role === 'user' && u.createdBy.toLowerCase() === activeSub.username.toLowerCase()
    );
    const pool = computeSubAdminPool(activeSub, mine);
    const { effectiveSettings } = resolveEffectiveModelSettings(modelSettings, activeSub);
    const inviteToken = signInviteToken({
      inviterId: activeSub.id,
      inviterRole: 'subadmin',
      v: subRecord?.inviteVersion || 1,
    });
    res.json({
      users: mine,
      pool,
      inviteToken,
      subAdmin: activeSub,
      engineSummary: {
        defaultImageEngine: modelSettings.imageEngine,
        defaultVoiceEngine: modelSettings.voiceEngine,
        effectiveImageEngine: effectiveSettings.imageEngine,
        effectiveVoiceEngine: effectiveSettings.voiceEngine,
        readiness,
      },
    });
  }));

  app.post('/api/subadmin/invite-link/reset', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const nextV = await rotateUserInviteVersion(req.authUser.id);
    if (!nextV) {
      res.status(400).json({ error: 'ইনভাইট লিংক রিসেট করা যায়নি।' });
      return;
    }
    const inviteToken = signInviteToken({
      inviterId: req.authUser.id,
      inviterRole: 'subadmin',
      v: nextV,
    });
    await appendActivityLog({
      actor: req.authUser.username,
      role: 'subadmin',
      action: 'সাব-অ্যাডমিন ইনভাইট লিংক রিসেট',
      detail: `ভার্সন #${nextV}`,
      status: 'warning',
    }).catch(() => {});
    res.json({ inviteToken });
  }));

  app.post('/api/subadmin/users/:id/approve', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const subAdmin = req.authUser;
    const { picLimit, voiceLimit, videoLimit, expiresInDays, imageApiOverride, voiceApiOverride } = req.body as {
      picLimit?: number;
      voiceLimit?: number;
      videoLimit?: number;
      expiresInDays?: number | null;
      imageApiOverride?: UserImageApiOption;
      voiceApiOverride?: UserVoiceApiOption;
    };
    const reqPic = parseFiniteQuotaInput(picLimit, 25);
    const reqVoice = parseFiniteQuotaInput(voiceLimit, 10);
    const reqVideo = parseFiniteQuotaInput(videoLimit, 3);
    if (reqPic === null || reqVoice === null || reqVideo === null) {
      res.status(400).json({ error: 'ইমেজ/ভয়েস/ভিডিও লিমিটের সংখ্যা সঠিক নয়।' });
      return;
    }

    const result = await withSubAdminPoolLock(subAdmin.id, async () => {
      const target = await findUserById(String(req.params.id));
      if (!target || target.role !== 'user' || target.createdBy.toLowerCase() !== subAdmin.username.toLowerCase()) {
        return { status: 404 as const, error: 'আপনার ইনভাইট লিংকের আবেদনকারী ইউজার পাওয়া যায়নি।' };
      }
      if (target.approvalStatus !== 'pending') {
        return { status: 400 as const, error: 'এই অ্যাকাউন্টটি ইতিমধ্যেই অনুমোদিত রয়েছে।' };
      }

      const [latestSub, all] = await Promise.all([findUserById(subAdmin.id), getAllUsers()]);
      const activeSub = latestSub || subAdmin;
      const mine = all.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === activeSub.username.toLowerCase()
      );
      const capCheck = validateSubAdminCreationLimits(activeSub, reqPic, reqVoice, reqVideo, mine);
      if (!capCheck.valid) {
        return { status: 400 as const, error: capCheck.message };
      }

      const updated = await updateUserById(target.id, {
        approvalStatus: 'approved',
        isActive: true,
        picLimit: reqPic,
        voiceLimit: reqVoice,
        videoLimit: reqVideo,
        allowMasterApi: activeSub.allowMasterApi,
        expiresAt: resolveExpiresAt(expiresInDays),
        ...(imageApiOverride !== undefined
          ? { imageApiOverride: normalizeUserImageApiOverride(imageApiOverride) }
          : {}),
        ...(voiceApiOverride !== undefined
          ? { voiceApiOverride: normalizeUserVoiceApiOverride(voiceApiOverride) }
          : {}),
      });
      if (!updated.ok) {
        return { status: 400 as const, error: updated.message };
      }
      const nextMine = mine.map((u) => (u.id === updated.user.id ? updated.user : u));
      const pool = computeSubAdminPool(activeSub, nextMine);
      return { status: 200 as const, user: updated.user, pool };
    });

    if (result.status !== 200) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    await appendActivityLog({
      actor: subAdmin.username,
      role: 'subadmin',
      action: 'ইনভাইট আবেদন একসেপ্ট',
      detail: `${result.user.username} (P:${reqPic}/V:${reqVoice}/Vid:${reqVideo})`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: result.user, pool: result.pool });
  }));

  app.post('/api/subadmin/users', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const subAdmin = req.authUser;
    const { username, email, password, picLimit, voiceLimit, videoLimit, expiresInDays, imageApiOverride, voiceApiOverride } =
      req.body as {
        username?: string;
        email?: string;
        password?: string;
        picLimit?: number;
        voiceLimit?: number;
        videoLimit?: number;
        expiresInDays?: number | null;
        imageApiOverride?: UserImageApiOption;
        voiceApiOverride?: UserVoiceApiOption;
      };
    if (!username || !email || !password) {
      res.status(400).json({ error: 'সব তথ্য পূরণ করুন!' });
      return;
    }
    if (!validateEmailFormat(email)) {
      res.status(400).json({ error: 'সঠিক ইমেইল অ্যাড্রেস দিন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    const passCheck = validatePasswordStrength(password, otpSettings.passwordPolicy);
    if (!passCheck.valid) {
      res.status(400).json({ error: passCheck.message });
      return;
    }

    const reqPic = parseFiniteQuotaInput(picLimit, 25);
    const reqVoice = parseFiniteQuotaInput(voiceLimit, 10);
    const reqVideo = parseFiniteQuotaInput(videoLimit, 3);
    if (reqPic === null || reqVoice === null || reqVideo === null) {
      res.status(400).json({ error: 'ইমেজ/ভয়েস/ভিডিও লিমিটের সংখ্যা সঠিক নয়।' });
      return;
    }

    const result = await withSubAdminPoolLock(subAdmin.id, async () => {
      const [latestSub, all] = await Promise.all([findUserById(subAdmin.id), getAllUsers()]);
      const activeSub = latestSub || subAdmin;
      const mine = all.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === activeSub.username.toLowerCase()
      );
      const capCheck = validateSubAdminCreationLimits(activeSub, reqPic, reqVoice, reqVideo, mine);
      if (!capCheck.valid) {
        return { status: 400 as const, error: capCheck.message };
      }
      const created = await createUser({
        username,
        email,
        password,
        role: 'user',
        createdBy: activeSub.username,
        picLimit: reqPic,
        voiceLimit: reqVoice,
        videoLimit: reqVideo,
        allowMasterApi: activeSub.allowMasterApi,
        isActive: true,
        imageApiOverride: normalizeUserImageApiOverride(imageApiOverride),
        voiceApiOverride: normalizeUserVoiceApiOverride(voiceApiOverride),
        expiresAt: resolveExpiresAt(expiresInDays),
      });
      if (!created.ok) {
        return { status: 400 as const, error: created.message };
      }
      const pool = computeSubAdminPool(activeSub, [...mine, created.user]);
      return { status: 201 as const, user: created.user, pool };
    });

    if (result.status !== 201) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    await appendActivityLog({
      actor: subAdmin.username,
      role: 'subadmin',
      action: 'সাব-অ্যাডমিন ইউজার তৈরি',
      detail: `${result.user.username} (P:${reqPic}/V:${reqVoice}/Vid:${reqVideo})`,
      status: 'success',
    }).catch(() => {});
    res.status(201).json({ user: result.user, pool: result.pool });
  }));

  app.patch('/api/subadmin/users/:id', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const subAdmin = req.authUser;
    const body = (req.body || {}) as {
      username?: string;
      email?: string;
      password?: string;
      picLimit?: number;
      voiceLimit?: number;
      videoLimit?: number;
      isActive?: boolean;
      expiresInDays?: number | null;
      expiresAt?: string | null;
      imageApiOverride?: UserImageApiOption;
      voiceApiOverride?: UserVoiceApiOption;
    };

    if (body.email !== undefined && !validateEmailFormat(body.email)) {
      res.status(400).json({ error: 'সঠিক ইমেইল অ্যাড্রেস দিন।' });
      return;
    }
    if (
      body.imageApiOverride !== undefined &&
      !USER_IMAGE_API_OPTIONS.some((opt) => opt.value === body.imageApiOverride)
    ) {
      res.status(400).json({ error: 'অবৈধ ইমেজ API অপশন।' });
      return;
    }
    if (
      body.voiceApiOverride !== undefined &&
      !USER_VOICE_API_OPTIONS.some((opt) => opt.value === body.voiceApiOverride)
    ) {
      res.status(400).json({ error: 'অবৈধ ভয়েস API অপশন।' });
      return;
    }
    const { otpSettings } = await getStudioSettings();
    if (body.password && body.password.trim().length > 0) {
      const passCheck = validatePasswordStrength(body.password, otpSettings.passwordPolicy);
      if (!passCheck.valid) {
        res.status(400).json({ error: passCheck.message });
        return;
      }
    }

    const parsedBodyPic = body.picLimit !== undefined ? parseFiniteQuotaInput(body.picLimit) : undefined;
    const parsedBodyVoice = body.voiceLimit !== undefined ? parseFiniteQuotaInput(body.voiceLimit) : undefined;
    const parsedBodyVideo = body.videoLimit !== undefined ? parseFiniteQuotaInput(body.videoLimit) : undefined;
    if (parsedBodyPic === null || parsedBodyVoice === null || parsedBodyVideo === null) {
      res.status(400).json({ error: 'ইমেজ/ভয়েস/ভিডিও লিমিটের সংখ্যা সঠিক নয়।' });
      return;
    }

    const result = await withSubAdminPoolLock(subAdmin.id, async () => {
      const target = await findUserById(String(req.params.id));
      if (!target || target.role !== 'user' || target.createdBy.toLowerCase() !== subAdmin.username.toLowerCase()) {
        return { status: 404 as const, error: 'আপনার তৈরি করা ইউজার পাওয়া যায়নি।' };
      }
      if (target.approvalStatus === 'pending') {
        return { status: 400 as const, error: 'অপেক্ষমাণ আবেদন এডিট করার আগে একসেপ্ট করুন অথবা বাতিল করুন।' };
      }

      const [latestSub, all] = await Promise.all([findUserById(subAdmin.id), getAllUsers()]);
      const activeSub = latestSub || subAdmin;
      const mine = all.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === activeSub.username.toLowerCase()
      );

      const nextPic = parsedBodyPic ?? target.picLimit;
      const nextVoice = parsedBodyVoice ?? target.voiceLimit;
      const nextVideo = parsedBodyVideo ?? target.videoLimit;

      if (nextPic < target.picsUsed || nextVoice < target.voicesUsed || nextVideo < target.videosUsed) {
        return { status: 400 as const, error: 'নতুন লিমিট ইতিমধ্যেই ব্যবহৃত সংখ্যার চেয়ে কম হতে পারবে না।' };
      }

      const limitsChanged =
        (parsedBodyPic !== undefined && nextPic !== target.picLimit) ||
        (parsedBodyVoice !== undefined && nextVoice !== target.voiceLimit) ||
        (parsedBodyVideo !== undefined && nextVideo !== target.videoLimit);

      if (limitsChanged) {
        const capCheck = validateSubAdminCreationLimits(
          activeSub,
          nextPic,
          nextVoice,
          nextVideo,
          mine,
          target.id
        );
        if (!capCheck.valid) {
          return { status: 400 as const, error: capCheck.message };
        }
      }

      const patch: Parameters<typeof updateUserById>[1] = {};
      if (body.username !== undefined) patch.username = body.username;
      if (body.email !== undefined) patch.email = body.email;
      if (body.password && body.password.trim().length > 0) patch.password = body.password;
      if (parsedBodyPic !== undefined) patch.picLimit = nextPic;
      if (parsedBodyVoice !== undefined) patch.voiceLimit = nextVoice;
      if (parsedBodyVideo !== undefined) patch.videoLimit = nextVideo;
      if (body.isActive !== undefined) patch.isActive = Boolean(body.isActive);
      if (body.expiresInDays !== undefined || body.expiresAt !== undefined) {
        patch.expiresAt = resolveExpiresAt(body.expiresInDays, body.expiresAt);
      }
      if (body.imageApiOverride !== undefined) {
        patch.imageApiOverride = normalizeUserImageApiOverride(body.imageApiOverride);
      }
      if (body.voiceApiOverride !== undefined) {
        patch.voiceApiOverride = normalizeUserVoiceApiOverride(body.voiceApiOverride);
      }

      const updated = await updateUserById(target.id, patch);
      if (!updated.ok) {
        return { status: 400 as const, error: updated.message };
      }
      const nextMine = mine.map((u) => (u.id === updated.user.id ? updated.user : u));
      const pool = computeSubAdminPool(activeSub, nextMine);
      return { status: 200 as const, user: updated.user, pool };
    });

    if (result.status !== 200) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    await appendActivityLog({
      actor: subAdmin.username,
      role: 'subadmin',
      action: 'সাব-অ্যাডমিন ইউজার আপডেট',
      detail: `${result.user.username} (${result.user.isActive ? 'Active' : 'Suspended'} · Img:${result.user.imageApiOverride || 'default'} / Voice:${result.user.voiceApiOverride || 'default'})`,
      status: 'success',
    }).catch(() => {});
    res.json({ user: result.user, pool: result.pool });
  }));

  app.post('/api/subadmin/users/:id/reset-quota', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const subAdmin = req.authUser;
    const result = await withSubAdminPoolLock(subAdmin.id, async () => {
      const target = await findUserById(String(req.params.id));
      if (!target || target.role !== 'user' || target.createdBy.toLowerCase() !== subAdmin.username.toLowerCase()) {
        return { status: 404 as const, error: 'আপনার তৈরি করা ইউজার পাওয়া যায়নি।' };
      }
      if (target.approvalStatus === 'pending') {
        return { status: 400 as const, error: 'অপেক্ষমাণ আবেদন একসেপ্ট করার আগে কোটা রিসেট করা যাবে না।' };
      }

      const [latestSub, allBefore] = await Promise.all([findUserById(subAdmin.id), getAllUsers()]);
      const activeSub = latestSub || subAdmin;
      const mineBefore = allBefore.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === activeSub.username.toLowerCase()
      );
      const resetCheck = validateSubAdminResetQuota(activeSub, target, mineBefore);
      if (!resetCheck.valid) {
        return { status: 400 as const, error: resetCheck.message };
      }

      const updatedSub =
        (target.picsUsed > 0 || target.voicesUsed > 0 || target.videosUsed > 0)
          ? await atomicIncrementUsage(activeSub.id, {
              pic: target.picsUsed,
              voice: target.voicesUsed,
              video: target.videosUsed,
            })
          : activeSub;
      const subForPool = updatedSub || activeSub;

      const updated = await resetUserUsageById(target.id);
      const all = await getAllUsers();
      const mine = all.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === subForPool.username.toLowerCase()
      );
      const pool = computeSubAdminPool(subForPool, mine);
      return { status: 200 as const, target, user: updated, pool, subAdmin: subForPool };
    });

    if (result.status !== 200) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    await appendActivityLog({
      actor: subAdmin.username,
      role: 'subadmin',
      action: 'ইউজার কোটা রিসেট',
      detail: result.target.username,
      status: 'success',
    }).catch(() => {});
    res.json({ user: result.user, pool: result.pool, subAdmin: result.subAdmin });
  }));

  app.delete('/api/subadmin/users/:id', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    if (req.authUser?.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const subAdmin = req.authUser;
    const result = await withSubAdminPoolLock(subAdmin.id, async () => {
      const target = await findUserById(String(req.params.id));
      if (!target || target.role !== 'user' || target.createdBy.toLowerCase() !== subAdmin.username.toLowerCase()) {
        return { status: 404 as const, error: 'আপনার তৈরি করা ইউজার পাওয়া যায়নি।' };
      }
      const latestSub = await findUserById(subAdmin.id);
      const activeSub = latestSub || subAdmin;
      const updatedSub =
        (target.picsUsed > 0 || target.voicesUsed > 0 || target.videosUsed > 0)
          ? await atomicIncrementUsage(activeSub.id, {
              pic: target.picsUsed,
              voice: target.voicesUsed,
              video: target.videosUsed,
            })
          : activeSub;
      const subForPool = updatedSub || activeSub;

      await deleteUserById(target.id);
      await cleanupSupportOnUserDelete(target.id).catch(() => {});
      const all = await getAllUsers();
      const mine = all.filter(
        (u) => u.role === 'user' && u.createdBy.toLowerCase() === subForPool.username.toLowerCase()
      );
      const pool = computeSubAdminPool(subForPool, mine);
      return { status: 200 as const, target, pool, subAdmin: subForPool };
    });

    if (result.status !== 200) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    await appendActivityLog({
      actor: subAdmin.username,
      role: 'subadmin',
      action: 'ইউজার ডিলিট',
      detail: result.target.username,
      status: 'warning',
    }).catch(() => {});
    res.json({ ok: true, pool: result.pool, subAdmin: result.subAdmin });
  }));

  // ==========================================
  // CROSS-BROWSER WORKSPACE & HISTORY ROUTES
  // ==========================================
  app.get('/api/studio/workspace', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const workspace = await getUserWorkspaceSnapshot(req.authUser!.id);
    res.json({ workspace });
  }));

  app.post('/api/studio/workspace/sync', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const body = (req.body || {}) as {
      sessionState?: StudioSessionDraft;
      poses?: PersistedPoseItem[];
      voices?: PersistedVoiceItem[];
      videos?: PersistedVideoItem[];
    };
    const workspace = await syncUserWorkspaceData(req.authUser!.id, body);
    res.json({ workspace });
  }));

  app.delete('/api/studio/history/:kind/:id', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const kind = String(req.params.kind);
    const itemId = String(req.params.id);
    if (kind !== 'pose' && kind !== 'voice' && kind !== 'video') {
      res.status(400).json({ error: 'অবৈধ মিডিয়া ধরন।' });
      return;
    }
    const workspace = await deleteUserHistoryItem(req.authUser!.id, kind, itemId);
    res.json({ workspace });
  }));

  app.delete('/api/studio/history/:kind', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const kind = String(req.params.kind);
    if (kind !== 'pose' && kind !== 'voice' && kind !== 'video') {
      res.status(400).json({ error: 'অবৈধ মিডিয়া ধরন।' });
      return;
    }
    const workspace = await clearUserHistoryKind(req.authUser!.id, kind);
    res.json({ workspace });
  }));

  // ==========================================
  // STUDIO GENERATION ROUTES (Sectors 1-10)
  // ==========================================
  app.post('/api/studio/generate-pose', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const { modelSettings, otpSettings } = await getStudioSettings();
    if (otpSettings.maintenanceMode && user.role !== 'main_admin') {
      res.status(503).json({
        error: otpSettings.maintenanceMessage || 'সিস্টেমে সাময়িক রক্ষণাবেক্ষণ চলছে। কিছুক্ষণ পর আবার চেষ্টা করুন।',
      });
      return;
    }

    const body = req.body as {
      sector: SectorId;
      preset: string;
      extraSubpose: string;
      carAction: string;
      carAddon: string;
      bgMode: 'keep' | 'preset' | 'upload';
      bgPreset: string;
      handPosition: 'front_face_side' | 'natural_same';
      cleanOldHand: boolean;
      paperText?: string;
      paperWritingStyle?: string;
      paperSize?: string;
      cardLabelText?: string;
      idCardName?: string;
      idCardDob?: string;
      idCardAddress?: string;
      useModelPhotoOnId?: boolean;
      docRefKind?: 'license' | 'bank_card';
      customPrompt?: string;
      realismProfile?: PoseRealismProfile;
      imageResolution?: ImageResolutionPreset;
      baseImageBase64: string;
      baseMimeType?: string;
      carImageBase64?: string;
      carMimeType?: string;
      docImageBase64?: string;
      docMimeType?: string;
      bgImageBase64?: string;
      bgMimeType?: string;
    };

    if (!body.baseImageBase64) {
      res.status(400).json({ error: 'মডেলের মূল ছবি আপলোড করুন!' });
      return;
    }

    const isBatch = body.sector === 'finger' && body.preset === 'multi_batch';
    const countNeeded = isBatch ? 4 : 1;

    // Resolve per-user / inherited Sub-Admin API engine override
    const { effectiveSettings, strictImageEngine } = await resolveUserGenerationSettings(user, modelSettings);
    const activeResolution: ImageResolutionPreset =
      user.role === 'main_admin' && (body.imageResolution === '512x512' || body.imageResolution === '1024x1024')
        ? body.imageResolution
        : normalizeImageResolution(effectiveSettings.deepinfraImageResolution);

    // Atomic up-front reservation prevents concurrent double-spend race conditions
    const reservation = await reserveUserQuota(user.id, { pic: countNeeded });
    if (!reservation.ok) {
      res.status(403).json({ error: reservation.message });
      return;
    }
    let updatedUser: PublicUser = reservation.user;

    const extraImages: Array<{ base64: string; mimeType?: string }> = [];
    if (body.sector === 'car' && body.carImageBase64) {
      extraImages.push({ base64: body.carImageBase64, mimeType: body.carMimeType || 'image/jpeg' });
    }
    if ((body.sector === 'license' || body.sector === 'card') && body.docImageBase64) {
      extraImages.push({ base64: body.docImageBase64, mimeType: body.docMimeType || 'image/jpeg' });
    }
    if (body.bgMode === 'upload' && body.bgImageBase64) {
      extraImages.push({ base64: body.bgImageBase64, mimeType: body.bgMimeType || 'image/jpeg' });
    }

    try {
      const results: PersistedPoseItem[] = [];
      let partialError: string | undefined;

      if (isBatch) {
        const batchList = [
          { key: 'one_finger', label: '☝️ ১ আঙুল ভেরিফিকেশন' },
          { key: 'two_finger', label: '✌️ ২ আঙুল ভেরিফিকেশন' },
          { key: 'three_finger', label: '🤟 ৩ আঙুল ভেরিফিকেশন' },
          { key: 'five_finger', label: '✋ ৫ আঙুল ভেরিফিকেশন' },
        ];
        for (const item of batchList) {
          try {
            const prompt = buildVerificationPrompt({
              ...body,
              preset: item.key,
              hasCustomBgImage: Boolean(body.bgImageBase64),
              hasCarRefImage: Boolean(body.carImageBase64),
              hasDocRefImage: Boolean(body.docImageBase64),
              docRefKind: body.docRefKind || (body.sector === 'card' ? 'bank_card' : 'license'),
            });
            const url = await generateStudioImage({
              prompt,
              baseImageBase64: body.baseImageBase64,
              baseMimeType: body.baseMimeType || 'image/jpeg',
              extraImages,
              settings: effectiveSettings,
              strictImageEngine,
              resolutionOverride: activeResolution,
            });
            const nowMs = Date.now();
            results.push({
              id: crypto.randomUUID(),
              url,
              label: item.label,
              sector: body.sector,
              createdAt: new Date(nowMs).toLocaleTimeString(),
              timestampMs: nowMs,
            });
          } catch (batchErr) {
            const unused = countNeeded - results.length;
            if (unused > 0) {
              const refunded = await refundUserQuota(user.id, { pic: unused });
              if (refunded) updatedUser = refunded;
            }
            if (results.length === 0) throw batchErr;
            partialError = `${batchList.length}টির মধ্যে ${results.length}টি ছবি তৈরি হয়েছে; বাকি অংশের ক্রেডিট ফেরত দেওয়া হয়েছে।`;
            break;
          }
        }
      } else {
        const prompt = buildVerificationPrompt({
          ...body,
          hasCustomBgImage: Boolean(body.bgImageBase64),
          hasCarRefImage: Boolean(body.carImageBase64),
          hasDocRefImage: Boolean(body.docImageBase64),
          docRefKind: body.docRefKind || (body.sector === 'card' ? 'bank_card' : 'license'),
        });
        const url = await generateStudioImage({
          prompt,
          baseImageBase64: body.baseImageBase64,
          baseMimeType: body.baseMimeType || 'image/jpeg',
          extraImages,
          settings: effectiveSettings,
          strictImageEngine,
          resolutionOverride: activeResolution,
        });
        const nowMs = Date.now();
        results.push({
          id: crypto.randomUUID(),
          url,
          label: SECTOR_META[body.sector]?.badge || 'Verified Pose',
          sector: body.sector,
          createdAt: new Date(nowMs).toLocaleTimeString(),
          timestampMs: nowMs,
        });
      }

      // Immediately persist generated poses server-side for refresh & cross-browser continuity
      await appendUserMediaHistory(user.id, { poses: results }).catch(() => {});

      await appendActivityLog({
        actor: user.username,
        role: user.role,
        action: `পোজ জেনারেশন (${body.sector})`,
        detail: `${results.length}টি ছবি (${effectiveSettings.imageEngine})`,
        status: partialError ? 'warning' : 'success',
      }).catch(() => {});

      res.json({ results, user: updatedUser, ...(partialError ? { partialError } : {}) });
    } catch (err) {
      if (!isBatch) {
        await refundUserQuota(user.id, { pic: countNeeded }).catch(() => {});
      }
      res.status(502).json({
        error: formatGenerationErrorForClient(err, user.role, 'ছবি তৈরি করতে সমস্যা হয়েছে। পরে আবার চেষ্টা করুন।'),
      });
    }
  }));

  app.post('/api/studio/translate-script', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const rl = checkRateLimit('voice_assist', user.id, 45, 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অনেকগুলো অনুবাদ রিকোয়েস্ট পাঠানো হয়েছে। ${rl.retryAfterSec} সেকেন্ড পর চেষ্টা করুন।` });
      return;
    }
    const { modelSettings, otpSettings } = await getStudioSettings();
    if (otpSettings.maintenanceMode && user.role !== 'main_admin') {
      res.status(503).json({
        error: otpSettings.maintenanceMessage || 'সিস্টেমে সাময়িক রক্ষণাবেক্ষণ চলছে। কিছুক্ষণ পর আবার চেষ্টা করুন।',
      });
      return;
    }
    if (!user.allowMasterApi && user.role !== 'main_admin') {
      res.status(403).json({ error: 'আপনার অ্যাকাউন্টে API অনুমোদন বন্ধ রয়েছে।' });
      return;
    }
    const parentApiCheck = await isParentSubAdminBlocked(user, true);
    if (parentApiCheck.blocked) {
      res.status(403).json({ error: parentApiCheck.reason || 'সাব-অ্যাডমিন API অনুমোদন বন্ধ রয়েছে।' });
      return;
    }

    const body = req.body as {
      text?: string;
      target?: VoiceTranslationTarget;
      country?: VoiceCountry;
      region?: string;
      maxWordsHint?: boolean;
    };
    if (!body.text?.trim()) {
      res.status(400).json({ error: 'অনুবাদ করার জন্য আগে স্ক্রিপ্ট লিখুন বা মুখে বলুন।' });
      return;
    }

    try {
      const { effectiveSettings } = await resolveUserGenerationSettings(user, modelSettings);
      const out = await translateStudioScript({
        text: body.text,
        target: body.target || 'auto_country',
        country: body.country || 'USA',
        region: body.region,
        maxWordsHint: Boolean(body.maxWordsHint),
        settings: effectiveSettings,
      });
      res.json(out);
    } catch (err) {
      res.status(502).json({
        error: formatGenerationErrorForClient(err, user.role, 'স্ক্রিপ্ট অনুবাদ করা যায়নি। আবার চেষ্টা করুন।'),
      });
    }
  }));

  app.post('/api/studio/transcribe-audio', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const rl = checkRateLimit('voice_assist', user.id, 45, 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অনেকগুলো ভয়েস-টু-টেক্সট রিকোয়েস্ট পাঠানো হয়েছে। ${rl.retryAfterSec} সেকেন্ড পর চেষ্টা করুন।` });
      return;
    }
    const { modelSettings, otpSettings } = await getStudioSettings();
    if (otpSettings.maintenanceMode && user.role !== 'main_admin') {
      res.status(503).json({
        error: otpSettings.maintenanceMessage || 'সিস্টেমে সাময়িক রক্ষণাবেক্ষণ চলছে। কিছুক্ষণ পর আবার চেষ্টা করুন।',
      });
      return;
    }
    if (!user.allowMasterApi && user.role !== 'main_admin') {
      res.status(403).json({ error: 'আপনার অ্যাকাউন্টে API অনুমোদন বন্ধ রয়েছে।' });
      return;
    }
    const parentApiCheck = await isParentSubAdminBlocked(user, true);
    if (parentApiCheck.blocked) {
      res.status(403).json({ error: parentApiCheck.reason || 'সাব-অ্যাডমিন API অনুমোদন বন্ধ রয়েছে।' });
      return;
    }

    const body = req.body as {
      audioBase64?: string;
      mimeType?: string;
      spokenLanguageHint?: string;
      translateTarget?: VoiceTranslationTarget;
      autoTranslate?: boolean;
      country?: VoiceCountry;
      region?: string;
      maxWordsHint?: boolean;
    };
    if (!body.audioBase64) {
      res.status(400).json({ error: 'ভয়েস অডিও ডেটা পাওয়া যায়নি।' });
      return;
    }

    try {
      const { effectiveSettings } = await resolveUserGenerationSettings(user, modelSettings);
      const out = await transcribeAudioToText({
        audioBase64: body.audioBase64,
        mimeType: body.mimeType || 'audio/webm',
        spokenLanguageHint: body.spokenLanguageHint,
        translateTarget: body.translateTarget || 'auto_country',
        autoTranslate: Boolean(body.autoTranslate),
        country: body.country || 'USA',
        region: body.region,
        maxWordsHint: Boolean(body.maxWordsHint),
        settings: effectiveSettings,
      });
      res.json(out);
    } catch (err) {
      res.status(502).json({
        error: formatGenerationErrorForClient(err, user.role, 'ভয়েস থেকে টেক্সট রূপান্তর করা যায়নি। আবার চেষ্টা করুন।'),
      });
    }
  }));

  app.post('/api/studio/generate-voice', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const { modelSettings, otpSettings } = await getStudioSettings();
    if (otpSettings.maintenanceMode && user.role !== 'main_admin') {
      res.status(503).json({
        error: otpSettings.maintenanceMessage || 'সিস্টেমে সাময়িক রক্ষণাবেক্ষণ চলছে। কিছুক্ষণ পর আবার চেষ্টা করুন।',
      });
      return;
    }

    const body = req.body as {
      scriptText?: string;
      country: VoiceCountry;
      region: string;
      persona: string;
      tone?: string;
      emotion?: VoiceEmotion;
      targetLanguage?: VoiceTranslationTarget;
      isMicClone?: boolean;
      micAudioBase64?: string;
      micAudioMime?: string;
      refAudioBase64?: string;
      refAudioMime?: string;
    };

    if (!body.isMicClone && !body.scriptText?.trim()) {
      res.status(400).json({ error: 'টেক্সট লিখুন অথবা মাইক্রোফোনে রেকর্ড করুন!' });
      return;
    }
    if (body.isMicClone && !body.micAudioBase64) {
      res.status(400).json({ error: 'আগে মাইক্রোফোনে অডিও রেকর্ড করুন!' });
      return;
    }

    const { effectiveSettings, strictVoiceEngine } = await resolveUserGenerationSettings(user, modelSettings);

    const reservation = await reserveUserQuota(user.id, { voice: 1 });
    if (!reservation.ok) {
      res.status(403).json({ error: reservation.message });
      return;
    }
    const updatedUser = reservation.user;

    try {
      const out = await generateRegionalVoice({
        scriptText: body.scriptText || '',
        country: body.country || 'USA',
        region: body.region || body.country || 'USA',
        persona: body.persona || 'Aoede',
        tone: body.tone || 'exact_clone',
        emotion: body.emotion || 'natural_conversational',
        targetLanguage: body.targetLanguage || 'auto_country',
        isMicClone: Boolean(body.isMicClone),
        micAudioBase64: body.micAudioBase64,
        micAudioMime: body.micAudioMime,
        refAudioBase64: body.refAudioBase64,
        refAudioMime: body.refAudioMime,
        settings: effectiveSettings,
        strictVoiceEngine,
      });
      const nowMs = Date.now();
      const savedVoice: PersistedVoiceItem = {
        id: crypto.randomUUID(),
        audioUrl: out.audioDataUrl,
        mimeType: out.mimeType,
        localizedScript: out.localizedScript,
        region: body.region || body.country,
        persona: out.engineLabel,
        createdAt: new Date(nowMs).toLocaleTimeString(),
        timestampMs: nowMs,
      };

      await appendUserMediaHistory(user.id, { voices: [savedVoice] }).catch(() => {});

      await appendActivityLog({
        actor: user.username,
        role: user.role,
        action: 'ভয়েস ক্লোন',
        detail: `${body.country || 'USA'} (${body.region || ''}) · ${effectiveSettings.voiceEngine}`,
        status: 'success',
      }).catch(() => {});
      res.json({
        voice: savedVoice,
        user: updatedUser,
      });
    } catch (err) {
      await refundUserQuota(user.id, { voice: 1 }).catch(() => {});
      res.status(502).json({
        error: formatGenerationErrorForClient(err, user.role, 'ভয়েস তৈরি করতে সমস্যা হয়েছে।'),
      });
    }
  }));

  app.post('/api/studio/generate-talking-video', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const { modelSettings, otpSettings } = await getStudioSettings();
    if (otpSettings.maintenanceMode && user.role !== 'main_admin') {
      res.status(503).json({
        error: otpSettings.maintenanceMessage || 'সিস্টেমে সাময়িক রক্ষণাবেক্ষণ চলছে। কিছুক্ষণ পর আবার চেষ্টা করুন।',
      });
      return;
    }

    const body = req.body as {
      imageBase64: string;
      imageMimeType?: string;
      callFrame: string;
      bgMode: 'keep' | 'preset' | 'upload';
      bgPreset: string;
      customBgBase64?: string;
      customBgMimeType?: string;
      country: VoiceCountry;
      region?: string;
      voiceTone: string;
      voiceEmotion?: VoiceEmotion;
      targetLanguage?: VoiceTranslationTarget;
      persona: string;
      dialogue: string;
      refVoiceBase64?: string;
      refVoiceMime?: string;
    };

    if (!body.imageBase64 || !body.dialogue?.trim()) {
      res.status(400).json({ error: 'মডেলের সেলফি ছবি এবং ডায়ালগ টেক্সট দিন।' });
      return;
    }

    const readiness = getServerEngineReadiness();
    if (!readiness.falConfigured) {
      res.status(400).json({
        error: 'সার্ভারে FAL_API_KEY সেট করা নেই। লিপ-সিঙ্ক ভিডিওর জন্য Secrets-এ FAL_API_KEY যোগ করুন।',
      });
      return;
    }

    const { effectiveSettings, strictImageEngine, strictVoiceEngine } = await resolveUserGenerationSettings(
      user,
      modelSettings
    );

    const reservation = await reserveUserQuota(user.id, { video: 1 });
    if (!reservation.ok) {
      res.status(403).json({ error: reservation.message });
      return;
    }
    const updatedUser = reservation.user;

    try {
      let sourceImageDataUrl = `data:${body.imageMimeType || 'image/jpeg'};base64,${body.imageBase64}`;
      if (body.bgMode !== 'keep') {
        const bgMap: Record<string, string> = {
          cozy_bedroom: 'a cozy modern bedroom with soft warm bedside lamp lighting',
          luxury_car: 'inside the front seat of a modern luxury car in natural daylight',
          coffee_shop: 'seated inside a warm aesthetic coffee shop cafe',
          hotel_balcony: 'on an upscale hotel balcony with soft city daylight',
          modern_office: 'inside a clean modern home office studio room',
        };
        const bgDesc =
          body.bgMode === 'upload' && body.customBgBase64
            ? 'Seamlessly place this exact person into the background shown in the second image, matching lighting and natural smartphone video call framing.'
            : `Seamlessly place this exact person into ${bgMap[body.bgPreset] || bgMap.cozy_bedroom}, framed like a natural ${body.callFrame.replace(/_/g, ' ')} front-camera video call.`;

        const bgPrompt = `CRITICAL IDENTITY LOCK: Preserve the exact face, facial features, eyes, hair, skin tone, and identity of the person with 100% accuracy. Keep her facing directly toward the camera ready to speak. ${bgDesc} Photorealistic smartphone selfie quality.`;

        sourceImageDataUrl = await generateStudioImage({
          prompt: bgPrompt,
          baseImageBase64: body.imageBase64,
          baseMimeType: body.imageMimeType || 'image/jpeg',
          extraImages:
            body.bgMode === 'upload' && body.customBgBase64
              ? [{ base64: body.customBgBase64, mimeType: body.customBgMimeType || 'image/jpeg' }]
              : [],
          settings: effectiveSettings,
          strictImageEngine,
        });
      }

      const voiceOut = await generateRegionalVoice({
        scriptText: body.dialogue,
        country: body.country || 'USA',
        region: body.region || body.country || 'USA',
        persona: body.persona || 'Aoede',
        tone: body.voiceTone || 'exact_clone',
        emotion: body.voiceEmotion || 'natural_conversational',
        targetLanguage: body.targetLanguage || 'auto_country',
        refAudioBase64: body.refVoiceBase64,
        refAudioMime: body.refVoiceMime,
        maxSecondsHint: true,
        settings: effectiveSettings,
        strictVoiceEngine,
      });

      const videoUrl = await generateLipSyncVideo({
        sourceImageDataUrl,
        audioDataUrl: voiceOut.audioDataUrl,
        settings: effectiveSettings,
      });

      const nowMs = Date.now();
      const savedVideo: PersistedVideoItem = {
        id: crypto.randomUUID(),
        videoUrl,
        dialogue: voiceOut.localizedScript,
        frameLabel: body.callFrame,
        bgTag: body.bgMode === 'keep' ? 'Original BG' : 'New BG',
        createdAt: new Date(nowMs).toLocaleTimeString(),
        timestampMs: nowMs,
      };

      await appendUserMediaHistory(user.id, { videos: [savedVideo] }).catch(() => {});

      await appendActivityLog({
        actor: user.username,
        role: user.role,
        action: 'টকিং ভিডিও কল',
        detail: `${body.callFrame} (${body.country})`,
        status: 'success',
      }).catch(() => {});
      res.json({
        video: savedVideo,
        user: updatedUser,
      });
    } catch (err) {
      await refundUserQuota(user.id, { video: 1 }).catch(() => {});
      res.status(502).json({
        error: formatGenerationErrorForClient(err, user.role, 'টকিং ভিডিও তৈরি করতে সমস্যা হয়েছে।'),
      });
    }
  }));

  // Safe SSRF-whitelisted cross-origin file download proxy (with manual redirect allowlist verification)
  app.get('/api/studio/proxy-download', requireAuth, asyncRoute(async (req, res) => {
    const rawUrl = String(req.query.url || '');
    const filename = String(req.query.filename || 'studio-media').replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!isAllowedProxyUrl(rawUrl)) {
      res.status(400).json({ error: 'অবৈধ ডাউনলোড URL।' });
      return;
    }
    const MAX_PROXY_BYTES = 45 * 1024 * 1024;
    try {
      let currentUrl = rawUrl;
      let upstream: globalThis.Response | null = null;
      for (let hop = 0; hop < 3; hop++) {
        const resp = await fetch(currentUrl, {
          redirect: 'manual',
          signal: AbortSignal.timeout(30000),
        });
        if (resp.status >= 300 && resp.status < 400) {
          const loc = resp.headers.get('location');
          if (!loc) {
            res.status(502).json({ error: 'অবৈধ রিডাইরেক্ট পাওয়া গেছে।' });
            return;
          }
          const resolvedRedirect = new URL(loc, currentUrl).toString();
          if (!isAllowedProxyUrl(resolvedRedirect)) {
            res.status(400).json({ error: 'অনুমোদিত নয় এমন রিডাইরেক্ট URL।' });
            return;
          }
          currentUrl = resolvedRedirect;
          continue;
        }
        upstream = resp;
        break;
      }
      if (!upstream || !upstream.ok) {
        res.status(502).json({ error: 'মিডিয়া ডাউনলোড করা যায়নি।' });
        return;
      }
      const declaredLength = Number(upstream.headers.get('content-length') || 0);
      if (Number.isFinite(declaredLength) && declaredLength > MAX_PROXY_BYTES) {
        res.status(413).json({ error: 'মিডিয়া ফাইলের আকার সীমার চেয়ে বেশি।' });
        return;
      }
      const rawType = (upstream.headers.get('content-type') || 'application/octet-stream').toLowerCase();
      const safeType =
        /^(image\/(png|jpe?g|webp|gif)|audio\/|video\/mp4|application\/octet-stream)/i.test(rawType) &&
        !/svg|html|javascript|xml/i.test(rawType)
          ? rawType
          : 'application/octet-stream';
      const arrBuf = await upstream.arrayBuffer();
      if (arrBuf.byteLength > MAX_PROXY_BYTES) {
        res.status(413).json({ error: 'মিডিয়া ফাইলের আকার সীমার চেয়ে বেশি।' });
        return;
      }
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Type', safeType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(Buffer.from(arrBuf));
    } catch {
      res.status(502).json({ error: 'ডাউনলোড প্রক্সি এরর।' });
    }
  }));

  // ==========================================
  // DEDICATED HIERARCHICAL SUPPORT SYSTEM ROUTES
  // ==========================================
  app.get('/api/support/overview', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const overview = await getSupportOverviewForUser(req.authUser!);
    res.json(overview);
  }));

  app.put('/api/support/channels', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    if (user.role !== 'main_admin' && user.role !== 'subadmin') {
      res.status(403).json({ error: 'শুধুমাত্র মেইন অ্যাডমিন বা সাব-অ্যাডমিন সাপোর্ট লিংক সেট করতে পারবেন।' });
      return;
    }
    const rl = checkRateLimit('support_cfg', user.id, 20, 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অনুগ্রহ করে ${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }

    const body = (req.body || {}) as Partial<SupportChannelConfig>;
    const linkFields: Array<{ key: keyof SupportChannelConfig; kind: SupportLinkKind; label: string }> = [
      { key: 'whatsappUrl', kind: 'whatsapp', label: 'WhatsApp লিংক/নম্বর' },
      { key: 'whatsappGroupUrl', kind: 'whatsapp_group', label: 'WhatsApp গ্রুপ লিংক' },
      { key: 'telegramUrl', kind: 'telegram', label: 'Telegram লিংক/ইউজারনেম' },
      { key: 'telegramGroupUrl', kind: 'telegram_group', label: 'Telegram গ্রুপ লিংক' },
      { key: 'messengerUrl', kind: 'messenger', label: 'Messenger লিংক' },
      { key: 'messengerGroupUrl', kind: 'messenger_group', label: 'Messenger গ্রুপ লিংক' },
    ];

    const normalized: Partial<SupportChannelConfig> = {
      supportNote: typeof body.supportNote === 'string' ? body.supportNote.trim().slice(0, 300) : '',
    };

    for (const item of linkFields) {
      const check = normalizeSupportLink(item.kind, String(body[item.key] || ''));
      if (!check.valid) {
        res.status(400).json({ error: `${item.label}: ${check.message || 'সঠিক নয়'}` });
        return;
      }
      normalized[item.key] = check.url;
    }

    const channels = await saveSupportChannelsForOwner(user.id, normalized);
    await appendActivityLog({
      actor: user.username,
      role: user.role,
      action: 'সাপোর্ট লিংক আপডেট',
      detail: 'WhatsApp / Telegram / Messenger লিংক সংরক্ষিত হয়েছে',
      status: 'success',
    }).catch(() => {});

    res.json({ channels });
  }));

  app.post('/api/support/messages', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    const rl = checkRateLimit('support_msg', user.id, 35, 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `অনেকগুলো মেসেজ পাঠানো হয়েছে। ${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }
    const body = (req.body || {}) as {
      targetThreadId?: string;
      recipientMemberId?: string;
      body?: string;
    };

    try {
      const result = await sendSupportMessage(user, {
        targetThreadId: typeof body.targetThreadId === 'string' ? body.targetThreadId.trim() : undefined,
        recipientMemberId: typeof body.recipientMemberId === 'string' ? body.recipientMemberId.trim() : undefined,
        body: typeof body.body === 'string' ? body.body : '',
      });
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'মেসেজ পাঠানো যায়নি।';
      const isForbidden = msg.includes('অনুমতি নেই') || msg.includes('নিজের অধীনে');
      res.status(isForbidden ? 403 : 400).json({ error: msg });
    }
  }));

  app.post('/api/support/threads/:threadId/read', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const thread = await markSupportThreadRead(req.authUser!, String(req.params.threadId || ''));
    res.json({ ok: Boolean(thread), thread });
  }));

  app.delete('/api/support/threads/:threadId', requireAuth, asyncRoute(async (req: AuthenticatedRequest, res) => {
    const user = req.authUser!;
    if (user.role !== 'main_admin' && user.role !== 'subadmin') {
      res.status(403).json({ error: 'অনুমতি নেই।' });
      return;
    }
    const rl = checkRateLimit('support_del', user.id, 20, 60 * 1000);
    if (!rl.allowed) {
      res.status(429).json({ error: `${rl.retryAfterSec} সেকেন্ড পর আবার চেষ্টা করুন।` });
      return;
    }
    try {
      const deleted = await deleteSupportThread(user, String(req.params.threadId || ''));
      if (!deleted) {
        res.status(404).json({ error: 'সাপোর্ট কনভার্সেশন পাওয়া যায়নি।' });
        return;
      }
      res.json({ ok: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'চ্যাট মুছে ফেলা যায়নি।';
      res.status(msg.includes('অনুমতি') ? 403 : 400).json({ error: msg });
    }
  }));

  // Ensure unknown /api/* paths return clean JSON 404 instead of SPA index.html
  app.all('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API রুট পাওয়া যায়নি।' });
  });

  // JSON API error handler so unhandled route errors never crash the Express server
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    console.error(`[API Error] ${req.method} ${req.path}:`, err);
    if (!res.headersSent) {
      const errObj = (err && typeof err === 'object' ? err : {}) as {
        status?: number;
        statusCode?: number;
        type?: string;
        message?: string;
      };
      const rawStatus = Number(errObj.status ?? errObj.statusCode ?? 500);
      if (rawStatus === 413 || errObj.type === 'entity.too.large') {
        res.status(413).json({
          error: 'আপলোড করা ফাইল বা ডেটার আকার অনেক বড় (সর্বোচ্চ ২৫ MB অনুমোদিত)। দয়া করে ছোট ফাইল দিন।',
        });
        return;
      }
      if (rawStatus === 400 && (errObj.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
        res.status(400).json({
          error: 'অবৈধ JSON রিকোয়েস্ট পাঠানো হয়েছে।',
        });
        return;
      }
      const status = Number.isFinite(rawStatus) && rawStatus >= 400 && rawStatus < 600 ? rawStatus : 500;
      const safeMessage =
        status >= 500
          ? 'সার্ভারে অপ্রত্যাশিত সমস্যা হয়েছে। দয়া করে আবার চেষ্টা করুন।'
          : err instanceof Error
          ? err.message
          : 'রিকোয়েস্ট প্রসেস করা যায়নি।';
      res.status(status).json({
        error: safeMessage,
      });
    }
  });

  // Vite middleware in dev (hmr: false prevents Port 24678 WebSocket port conflict) / static build in prod
  if (process.env.NODE_ENV !== 'production') {
    process.env.DISABLE_HMR = 'true';
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    const indexHtmlPath = path.join(distDir, 'index.html');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      if (!fs.existsSync(indexHtmlPath)) {
        res.status(503).json({
          error: 'ফ্রন্টএন্ড বিল্ড (dist/index.html) পাওয়া যায়নি। প্রথমে npm run build চালান।',
        });
        return;
      }
      res.sendFile(indexHtmlPath);
    });
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`VeriFace & Voice Studio listening on http://0.0.0.0:${port}`);
  });
}

process.on('unhandledRejection', (reason) => {
  console.error('[Unhandled Rejection]', reason);
});

startServer();
