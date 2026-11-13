/** Uniform API error shape: { error: { code, message, details? } }. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter?: number;
  /** Optional structured context (e.g. { question_id } or { field }) so
   *  clients can attach the error to the offending input. */
  details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

export function badRequest(message: string, details?: Record<string, unknown>): ApiError {
  const err = new ApiError(400, "BAD_REQUEST", message);
  if (details) err.details = details;
  return err;
}

export function unauthorized(code: string, message: string): ApiError {
  return new ApiError(401, code, message);
}

export function forbidden(message: string): ApiError {
  return new ApiError(403, "FORBIDDEN", message);
}

export function notFound(message = "Not found"): ApiError {
  return new ApiError(404, "NOT_FOUND", message);
}

export function conflict(code: string, message: string): ApiError {
  return new ApiError(409, code, message);
}

export function payloadTooLarge(message: string): ApiError {
  return new ApiError(413, "PAYLOAD_TOO_LARGE", message);
}

export function tooManyRequests(retryAfter: number): ApiError {
  return new ApiError(
    429,
    "RATE_LIMITED",
    "Too many requests. Please try again later.",
    retryAfter,
  );
}
