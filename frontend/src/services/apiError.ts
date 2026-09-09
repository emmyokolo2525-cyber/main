/**
 * apiError — parse API error envelopes safely.
 *
 * The backend always returns `{"error": "human-readable string"}` on failure.
 * This helper reads that message so the frontend can surface actionable
 * feedback instead of generic fallback text.
 *
 * Security: HTML tags are stripped to prevent XSS if a malicious server
 * returns markup. Messages are truncated to a reasonable length.
 */

const MAX_ERROR_LENGTH = 500

function stripHtml(input: string): string {
  return input.replace(/<[^>]*>/g, '')
}

function truncate(input: string): string {
  if (input.length <= MAX_ERROR_LENGTH) return input
  return input.slice(0, MAX_ERROR_LENGTH) + '…'
}

/**
 * Extract a human-readable error message from a non-OK API Response.
 *
 * Handles the known envelope shape `{ error: string | { message: string } }`
 * and returns a safe, plain-text fallback for anything else.
 */
export async function parseApiError(
  response: Response,
  fallback: string,
): Promise<string> {
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return fallback
  }

  if (body == null || typeof body !== 'object') return fallback

  const record = body as Record<string, unknown>
  const raw = record.error

  let text: string | undefined
  if (typeof raw === 'string') {
    text = raw
  } else if (raw != null && typeof raw === 'object') {
    const inner = (raw as Record<string, unknown>).message
    if (typeof inner === 'string') text = inner
  }

  if (!text || text.trim().length === 0) return fallback

  return truncate(stripHtml(text.trim()))
}
