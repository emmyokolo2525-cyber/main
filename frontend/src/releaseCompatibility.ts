export const COMPATIBILITY_RELEASE_ID = 'harpocrates-1.0.0'
export const COMPATIBILITY_NETWORK = 'testnet'

/** Fail closed before a proof or transaction can cross a release boundary. */
export function assertReleaseCompatibility(): void {
  const releaseId = import.meta.env.VITE_HARPOCRATES_RELEASE_ID ?? COMPATIBILITY_RELEASE_ID
  const network = import.meta.env.VITE_HARPOCRATES_RELEASE_NETWORK ?? COMPATIBILITY_NETWORK

  if (releaseId !== COMPATIBILITY_RELEASE_ID || network !== COMPATIBILITY_NETWORK) {
    throw new Error('This frontend is not configured for the approved Harpocrates compatibility release.')
  }
}
