import { describe, it, expect, vi } from 'vitest'
import { parseApiError } from './apiError'

function makeResponse(body: unknown, ok = false): Response {
  return {
    ok,
    json: () => Promise.resolve(body),
  } as unknown as Response
}

function makeTextResponse(): Response {
  return {
    ok: false,
    json: () => Promise.reject(new SyntaxError('Unexpected token')),
  } as unknown as Response
}

describe('parseApiError', () => {
  const FALLBACK = 'Something went wrong.'

  it('returns the string error from the standard envelope', async () => {
    const res = makeResponse({ error: 'video payload exceeds size limit' })
    expect(await parseApiError(res, FALLBACK)).toBe('video payload exceeds size limit')
  })

  it('returns the nested message when error is an object', async () => {
    const res = makeResponse({ error: { message: 'API key has expired' } })
    expect(await parseApiError(res, FALLBACK)).toBe('API key has expired')
  })

  it('returns fallback when body has no error field', async () => {
    const res = makeResponse({ message: 'unknown' })
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('returns fallback when error is an empty string', async () => {
    const res = makeResponse({ error: '' })
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('returns fallback when error is null', async () => {
    const res = makeResponse({ error: null })
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('returns fallback when JSON parsing fails', async () => {
    const res = makeTextResponse()
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('returns fallback when body is null', async () => {
    const res = makeResponse(null)
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('returns fallback when body is a primitive', async () => {
    const res = makeResponse('oops')
    expect(await parseApiError(res, FALLBACK)).toBe(FALLBACK)
  })

  it('strips HTML tags from error messages', async () => {
    const res = makeResponse({ error: '<script>alert(1)</script>bad input' })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('bad input')
    expect(msg).not.toContain('<script>')
  })

  it('strips nested HTML in object-style errors', async () => {
    const res = makeResponse({ error: { message: '<b>server</b> error' } })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('server error')
  })

  it('truncates very long error messages', async () => {
    const longMsg = 'x'.repeat(600)
    const res = makeResponse({ error: longMsg })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toHaveLength(501) // 500 + '…'
    expect(msg.endsWith('…')).toBe(true)
  })

  it('does not truncate messages under the limit', async () => {
    const msg300 = 'y'.repeat(300)
    const res = makeResponse({ error: msg300 })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe(msg300)
  })

  it('trims whitespace from the error message', async () => {
    const res = makeResponse({ error: '  session not found  ' })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('session not found')
  })
})
