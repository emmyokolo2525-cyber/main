/**
 * Time attestation types and utilities for Harpocrates evidence protocol.
 * 
 * Supports claimed, observed, and independently anchored timestamps
 * (Stellar ledger and RFC 3161 TSA).
 */

export type TimeSourceType = 'claimed' | 'observed' | 'stellar_ledger' | 'rfc3161_tsa'

export type VerificationStatus = 'valid' | 'invalid' | 'unverified' | 'expired' | 'untrusted'

export type RiskLevel = 'none' | 'low' | 'medium' | 'high'

export interface ClaimedTime {
  unixMs: number
  sourceLabel: string
  uncertaintyMs: number
}

export interface ObservedTime {
  unixMs: number
  sourceLabel: string
}

export interface StellarAnchor {
  ledgerSequence: number
  ledgerTimestamp: number
  transactionHash: string
  networkPassphrase: string
}

export interface RFC3161Anchor {
  tokenBytes: string
  tsaUrl: string
  genTime: number
  policyOid?: string
  certFingerprint?: string
  verificationStatus: VerificationStatus
  verificationError?: string
}

export interface TimeAttestation {
  version: number
  protocol: string
  evidenceDigest: string
  claimedTime?: ClaimedTime
  observedTime?: ObservedTime
  stellarAnchors: StellarAnchor[]
  rfc3161Anchors: RFC3161Anchor[]
}

export interface RiskAssessment {
  risk_level: RiskLevel
  reasons: string[]
  recommendations: string[]
}

export interface CreateTimeAttestationRequest {
  evidenceDigest: string
  claimedTimeMs?: number
  claimedSourceLabel?: string
  uncertaintyMs?: number
}

export interface CreateTimeAttestationResponse {
  ok: boolean
  timeAttestation: TimeAttestation
  riskAssessment: RiskAssessment
}

export interface AnchorTimeAttestationRequest {
  timeAttestation: TimeAttestation
  stellarAnchor?: Omit<StellarAnchor, 'ledgerSequence' | 'ledgerTimestamp'> & {
    ledgerSequence: number
    ledgerTimestamp: number
  }
  rfc3161Anchor?: Omit<RFC3161Anchor, 'genTime'> & { genTime: number }
}

export interface ValidateTimeAttestationRequest {
  evidenceDigest: string
  timeAttestation: TimeAttestation
}

export interface ValidateTimeAttestationResponse {
  ok: boolean
  errors: string[]
  riskAssessment: RiskAssessment
}

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'

/**
 * Create a new time attestation with claimed and observed times.
 */
export async function createTimeAttestation(
  request: CreateTimeAttestationRequest,
): Promise<CreateTimeAttestationResponse> {
  const response = await fetch(`${API_BASE}/api/time-attestation/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || 'Failed to create time attestation')
  }

  return response.json()
}

/**
 * Add Stellar or RFC 3161 anchors to an existing time attestation.
 */
export async function anchorTimeAttestation(
  request: AnchorTimeAttestationRequest,
): Promise<CreateTimeAttestationResponse> {
  const response = await fetch(`${API_BASE}/api/time-attestation/anchor`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || 'Failed to anchor time attestation')
  }

  return response.json()
}

/**
 * Validate a time attestation against an evidence digest.
 */
export async function validateTimeAttestation(
  request: ValidateTimeAttestationRequest,
): Promise<ValidateTimeAttestationResponse> {
  const response = await fetch(`${API_BASE}/api/time-attestation/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || 'Failed to validate time attestation')
  }

  return response.json()
}

/**
 * Format a Unix millisecond timestamp for display.
 */
export function formatTimestamp(unixMs: number): string {
  const date = new Date(unixMs)
  return date.toISOString()
}

/**
 * Calculate time drift between two timestamps in seconds.
 */
export function calculateDrift(timeA: number, timeB: number): number {
  return Math.abs(timeA - timeB) / 1000
}

/**
 * Get a human-readable description of the risk level.
 */
export function describeRiskLevel(level: RiskLevel): string {
  switch (level) {
    case 'none':
      return 'No backdating risk detected'
    case 'low':
      return 'Low backdating risk'
    case 'medium':
      return 'Medium backdating risk - review recommended'
    case 'high':
      return 'High backdating risk - manual verification required'
  }
}

/**
 * Get the highest assurance time source from an attestation.
 */
export function getHighestAssuranceTime(attestation: TimeAttestation): {
  timestamp: number
  source: string
  assurance: 'high' | 'medium' | 'low'
} {
  // Highest assurance: Stellar anchor
  if (attestation.stellarAnchors.length > 0) {
    const anchor = attestation.stellarAnchors[0]
    return {
      timestamp: anchor.ledgerTimestamp * 1000,
      source: `Stellar Ledger #${anchor.ledgerSequence}`,
      assurance: 'high',
    }
  }

  // High assurance: Valid RFC 3161 token
  const validRFC3161 = attestation.rfc3161Anchors.find((a) => a.verificationStatus === 'valid')
  if (validRFC3161) {
    return {
      timestamp: validRFC3161.genTime,
      source: `RFC 3161 TSA: ${validRFC3161.tsaUrl}`,
      assurance: 'high',
    }
  }

  // Medium assurance: Observed time
  if (attestation.observedTime) {
    return {
      timestamp: attestation.observedTime.unixMs,
      source: `Backend: ${attestation.observedTime.sourceLabel}`,
      assurance: 'medium',
    }
  }

  // Low assurance: Claimed time
  if (attestation.claimedTime) {
    return {
      timestamp: attestation.claimedTime.unixMs,
      source: `Device: ${attestation.claimedTime.sourceLabel}`,
      assurance: 'low',
    }
  }

  throw new Error('No time sources in attestation')
}

/**
 * Check if an attestation has independent anchors.
 */
export function hasIndependentAnchor(attestation: TimeAttestation): boolean {
  return attestation.stellarAnchors.length > 0 || attestation.rfc3161Anchors.length > 0
}

/**
 * Get a summary of all time sources in an attestation.
 */
export function summarizeTimeSources(attestation: TimeAttestation): {
  claimed?: string
  observed?: string
  anchors: string[]
} {
  const summary: { claimed?: string; observed?: string; anchors: string[] } = {
    anchors: [],
  }

  if (attestation.claimedTime) {
    summary.claimed = formatTimestamp(attestation.claimedTime.unixMs)
  }

  if (attestation.observedTime) {
    summary.observed = formatTimestamp(attestation.observedTime.unixMs)
  }

  for (const anchor of attestation.stellarAnchors) {
    summary.anchors.push(
      `Stellar: ${formatTimestamp(anchor.ledgerTimestamp * 1000)} (Ledger #${anchor.ledgerSequence})`,
    )
  }

  for (const anchor of attestation.rfc3161Anchors) {
    summary.anchors.push(`RFC 3161: ${formatTimestamp(anchor.genTime)} (${anchor.verificationStatus})`)
  }

  return summary
}
