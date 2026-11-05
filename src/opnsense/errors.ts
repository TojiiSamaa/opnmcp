export type ErrorType =
  | 'write_disabled'
  | 'blocked_endpoint'
  | 'not_read_only'
  | 'sensitive_disabled'
  | 'invalid_path'
  | 'invalid_input'
  | 'auth_failed'
  | 'forbidden'
  | 'not_found'
  | 'bad_request'
  | 'validation_failed'
  | 'upstream_error'
  | 'bad_response'
  | 'tls_error'
  | 'unreachable'
  | 'timeout'
  | 'config_error'
  | 'user_cancelled'
  | 'no_pending_change'
  | 'rollback_blocked'
  | 'rollback_failed'
  | 'lockout_risk'
  | 'change_in_progress';

/**
 * Every failure carries a type and, where it helps, a hint telling the agent what
 * to do next (and just as importantly what not to retry).
 */
export class OpnsenseError extends Error {
  constructor(
    readonly type: ErrorType,
    message: string,
    readonly options: { hint?: string; status?: number; details?: unknown } = {},
  ) {
    super(message);
    this.name = 'OpnsenseError';
  }

  get status(): number | undefined {
    return this.options.status;
  }

  get hint(): string | undefined {
    return this.options.hint;
  }

  toJSON(): Record<string, unknown> {
    return {
      error: this.message,
      error_type: this.type,
      ...(this.options.status !== undefined ? { http_status: this.options.status } : {}),
      ...(this.options.hint ? { hint: this.options.hint } : {}),
      ...(this.options.details !== undefined ? { details: this.options.details } : {}),
    };
  }
}
