export const LIMITS = {
  auth: {
    // Access token lifetime in seconds.
    // 访问令牌有效期（秒）。
    accessTokenTtlSeconds: 7200,
    // Refresh sessions use a reusable opaque token with a sliding idle lifetime.
    // 刷新会话使用可复用的随机令牌，并按客户端采用滑动空闲期限。
    refreshTokenWebSlidingTtlMs: 30 * 24 * 60 * 60 * 1000,
    refreshTokenDefaultSlidingTtlMs: 30 * 24 * 60 * 60 * 1000,
    refreshTokenMobileSlidingTtlMs: 90 * 24 * 60 * 60 * 1000,
    // Hard upper bound for one login session, regardless of sliding refreshes.
    // 单次登录会话的绝对最长寿命，不因滑动续期突破该上限。
    refreshTokenAbsoluteTtlMs: 365 * 24 * 60 * 60 * 1000,
    // Refresh token random byte length.
    // 刷新令牌随机字节长度。
    refreshTokenRandomBytes: 32,
    // Attachment download token lifetime in seconds.
    // 附件下载令牌有效期（秒）。
    fileDownloadTokenTtlSeconds: 300,
    // Send access token lifetime in seconds.
    // Send 访问令牌有效期（秒）。
    sendAccessTokenTtlSeconds: 300,
    // Minimum required JWT secret length.
    // JWT 密钥最小长度要求。
    jwtSecretMinLength: 32,
    // Default PBKDF2 iterations for account creation/prelogin fallback.
    // 账户创建与预登录回退使用的默认 PBKDF2 迭代次数。
    defaultKdfIterations: 600000,
    // clientSecret length
    // clientSecret 长度
    clientSecretLength: 30,
  },
  rateLimit: {
    // Max failed login attempts before temporary lock.
    // 触发临时锁定前允许的最大登录失败次数。
    loginMaxAttempts: 10,
    // Login lock duration in minutes.
    // 登录锁定时长（分钟）。
    loginLockoutMinutes: 2,
    // Authenticated API request budget per user per minute (all reads & writes combined).
    // 认证 API 每用户每分钟请求配额（读写合计）。
    apiRequestsPerMinute: 200,
    // Public (unauthenticated) request budget per IP per minute.
    // 公开（未认证）接口每 IP 每分钟请求配额。
    publicRequestsPerMinute: 60,
    // Public read-only request budget per IP per minute.
    // 公开只读接口每 IP 每分钟请求配额。
    publicReadRequestsPerMinute: 120,
    // Public website icon proxy budget per IP per minute.
    // 公开网站图标代理每 IP 每分钟请求配额。
    publicIconRequestsPerMinute: 500,
    // Sensitive public/auth request budget per IP per minute.
    // 敏感公开/认证接口每 IP 每分钟请求配额。
    sensitivePublicRequestsPerMinute: 30,
    // Password hint lookup budget per IP per minute.
    // 密码提示查询接口每 IP 每分钟请求配额。
    passwordHintRequestsPerMinute: 1,
    // Password hint lookup budget per IP per hour.
    // 密码提示查询接口每 IP 每小时请求配额。
    passwordHintRequestsPerHour: 3,
    // Register endpoint budget per IP per minute.
    // 注册接口每 IP 每分钟请求配额。
    registerRequestsPerMinute: 5,
    // Refresh-token grant budget per IP per minute.
    // refresh_token 授权每 IP 每分钟请求配额。
    refreshTokenRequestsPerMinute: 30,
    // Coarser IP budget; the per-session budget above remains the primary guard.
    // 更宽松的 IP 总预算；主要保护仍由每个 refresh session 的预算承担。
    refreshTokenRequestsPerIpMinute: 300,
    // Passwordless/auth-request creation budget per IP/email/device per minute.
    // 免密/设备审批请求创建接口每 IP/邮箱/设备每分钟配额。
    authRequestRequestsPerMinute: 5,
    // SCIM provisioning request budget per IP per minute.
    // SCIM 供给接口每 IP 每分钟请求配额。
    scimRequestsPerMinute: 120,
    // Fixed window size for API rate limiting in seconds.
    // API 限流固定窗口大小（秒）。
    apiWindowSeconds: 60,
    // Probability to run low-frequency cleanup on request path.
    // 在请求路径中触发低频清理的概率。
    cleanupProbability: 0.05,
    // Minimum interval between login-attempt cleanup runs.
    // 登录尝试表清理的最小间隔。
    loginIpCleanupIntervalMs: 10 * 60 * 1000,
    // Retention window for login IP records.
    // 登录 IP 记录保留时长。
    loginIpRetentionMs: 30 * 24 * 60 * 60 * 1000,
  },
  cleanup: {
    // Minimum interval between refresh-token cleanup runs.
    // refresh_token 表清理最小间隔。
    refreshTokenCleanupIntervalMs: 30 * 60 * 1000,
    // Minimum interval between used attachment token cleanup runs.
    // 已使用附件令牌表清理最小间隔。
    attachmentTokenCleanupIntervalMs: 10 * 60 * 1000,
    // Probability to trigger cleanup during requests.
    // 请求过程中触发清理的概率。
    cleanupProbability: 0.05,
  },
  attachment: {
    // Max attachment upload size in bytes.
    // 附件上传大小上限（字节）。
    maxFileSizeBytes: 100 * 1024 * 1024,
  },
  send: {
    // Max file size allowed for Send file uploads.
    // Send 文件上传大小上限。
    maxFileSizeBytes: 100 * 1024 * 1024,
    // Max days allowed between now and a *finite* deletion date. Ten years.
    // 允许的最远删除日期（距当前天数）。
    //
    // This bound is not product policy about how long a link may live; it is a
    // sanity check that a finite date is a plausible one. Two mistakes reach
    // this field in practice -- a mistyped year (2226 for 2026) and a
    // seconds-vs-milliseconds epoch mix-up -- and both land centuries out, so a
    // decade rejects them without second-guessing a sender who genuinely wants
    // a link to outlive a year. Clients offer at most twelve months of preset
    // lifetimes plus a date the user picks, so nothing this server ships
    // against comes near the ceiling by accident.
    //
    // Raised from 31 because 31 was never a real bound either: it was the
    // upstream Bitwarden cloud's quota copied into a self-hosted server that
    // has no quota, and it made "keep this link for a quarter" impossible to
    // express. "Forever" is NOT expressed by pushing this number up -- it has
    // its own value, `neverDeletionDate` below.
    maxDeletionDays: 3653,
    // The one deletion date that means "this Send does not expire".
    //
    // A sentinel instant rather than a null column. `deletionDate` is NOT NULL
    // in the D1 schema and in `storage-schema.ts`, every read path
    // (`isSendAvailable`, `incrementSendAccessCount`'s `deletion_date > ?`) and
    // both response mappers treat it as a string that is always there, and
    // other Bitwarden clients render it without a null branch. Nulling it would
    // mean a migration, four call-site changes and a wire shape existing
    // clients have never seen; the sentinel changes nothing anywhere and is
    // still true, because this server runs no cleanup job -- a Send whose
    // deletion date is in the year 9999 is a Send that genuinely never expires.
    //
    // 9999-12-31T23:59:59.999Z specifically: it is the largest four-digit-year
    // ISO instant, it round-trips exactly through `new Date(..).toISOString()`,
    // and it sorts last lexicographically among ISO `Z` strings -- which is
    // what the SQL comparison and `idx_sends_user_deletion` actually do.
    neverDeletionDate: '9999-12-31T23:59:59.999Z',
  },
  organizations: {
    // Organizations a single account may own. Creating one grants premium
    // features, so the count is bounded.
    // 单个账户可创建的组织数量上限。创建组织会授予高级功能，因此需要限制数量。
    maxOwnedPerUser: 5,
    // Default and maximum SCIM page sizes.
    // SCIM 分页的默认值与上限。
    scimDefaultPageSize: 100,
    scimMaxPageSize: 500,
  },
  pagination: {
    // Default page size when client does not specify pageSize.
    // 客户端未传 pageSize 时的默认分页大小。
    defaultPageSize: 100,
    // Hard maximum page size accepted by server.
    // 服务端允许的最大分页大小。
    maxPageSize: 500,
  },
  cors: {
    // Browser preflight cache max age in seconds.
    // 浏览器预检请求缓存时长（秒）。
    preflightMaxAgeSeconds: 86400,
  },
  cache: {
    // Icon proxy cache TTL in seconds. Only a real icon earns it.
    // 图标代理缓存时长（秒），仅对真实图标生效。
    iconTtlSeconds: 604800,
    // Cache TTL for an icon miss: the placeholder, the 404, and upstream
    // error statuses. A timeout is a fact about one second, not about the
    // domain, so it must expire in minutes rather than in a week.
    // 图标兜底（占位图 / 404 / 上游错误状态）缓存时长（秒）。超时只说明当下这一刻，
    // 并非该域名本身没有图标，因此只缓存数分钟而不是一周。
    iconFallbackTtlSeconds: 300,
    // In-memory /api/sync response cache TTL (milliseconds).
    // /api/sync 内存缓存有效期（毫秒）。
    syncResponseTtlMs: 30 * 1000,
    // Max size of a single cached /api/sync body in bytes.
    // 单个 /api/sync 缓存响应允许的最大字节数。
    syncResponseMaxBodyBytes: 512 * 1024,
    // Max total in-memory bytes used by /api/sync cache per isolate.
    // 每个 isolate 中 /api/sync 缓存允许占用的最大总字节数。
    syncResponseMaxTotalBytes: 2 * 1024 * 1024,
    // Max in-memory /api/sync cache entries per isolate.
    // 每个 isolate 的 /api/sync 最大缓存条目数。
    syncResponseMaxEntries: 64,
  },
  performance: {
    // Max IDs per SQL batch when moving ciphers in bulk.
    // 批量移动密码项时每批 SQL 的最大 ID 数量。
    bulkMoveChunkSize: 200,
    // Max total items (folders + ciphers) allowed in a single import.
    // 单次导入允许的最大条目数（文件夹 + 密码项合计）。
    importItemLimit: 5000,
    // Small fixed concurrency for blob/attachment batch cleanup work.
    // 附件 / blob 批量清理时的保守并发数。
    attachmentDeleteConcurrency: 4,
  },
  request: {
    // Hard body size limit for JSON API endpoints (bytes). File upload paths are exempt.
    // JSON 接口请求 body 大小上限（字节），文件上传接口除外。
    maxBodyBytes: 25 * 1024 * 1024,
  },
  compatibility: {
    // Single source of truth for /config.version and /api/version.
    // /config.version 与 /api/version 的统一版本号来源。
    // Vaultwarden 1.37.0 advertises 2026.6.0 after aligning its API response
    // with the response contract required by Bitwarden 2026.7.x clients.
    bitwardenServerVersion: '2026.6.0',
    // Official 2026.4.x clients need this flag to receive and use cipher.key.
    // Hiding existing item keys makes item-key encrypted vault data unreadable.
    // 官方 2026.4.x 客户端需要该开关来接收并使用 cipher.key。
    // 隐藏已有逐项密钥会导致逐项密钥加密的密码库数据无法解密。
    cipherKeyEncryptionFeatureEnabled: true,
  },
} as const;

export function getRefreshTokenSlidingTtlMs(clientType?: string | null): number {
  const normalized = String(clientType || '').trim().toLowerCase();
  if (normalized === 'web') return LIMITS.auth.refreshTokenWebSlidingTtlMs;
  if (normalized === 'mobile') return LIMITS.auth.refreshTokenMobileSlidingTtlMs;
  return LIMITS.auth.refreshTokenDefaultSlidingTtlMs;
}
