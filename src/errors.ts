/** Uniform API error shape: { error: { code, message } }. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly headers?: Record<string, string>;

  constructor(
    status: number,
    code: string,
    message: string,
    headers?: Record<string, string>,
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export function tooManyRequests(message: string, retryAfterSeconds: number): ApiError {
  return new ApiError(429, "RATE_LIMITED", message, {
    "retry-after": String(Math.max(1, Math.ceil(retryAfterSeconds))),
  });
}

export function badRequest(message: string): ApiError {
  return new ApiError(400, "BAD_REQUEST", message);
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
