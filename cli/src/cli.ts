#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises'
import process from 'node:process'
import { createProofManifest, parseManifest, serializeManifest } from './manifest.js'
import { validateMetadata, fileHash, canonicalMetadataHash, type HarpocratesMetadata } from './metadata.js'
import { sha256 } from './hashing.js'
import { lookupByVideoHash, verifyTransaction } from './stellar-lookup.js'
import { createReceipt, formatReceipt, type VerificationReceipt } from './receipt.js'
import { computeResult } from './normalize.js'

// ── CLI argument parsing ──────────────────────────────────────────────────

type Command = 'verify' | 'manifest' | 'hash' | 'help'

function parseArgs(argv: string[]): {
  command: Command
  flags: Record<string, string>
} {
  if (argv.length < 1) {
    return { command: 'help', flags: {} }
  }

  const command = argv[0] as Command
  const flags: Record<string, string> = {}

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      if (eq >= 0) {
        flags[arg.slice(2, eq)] = arg.slice(eq + 1)
      } else {
        const key = arg.slice(2)
        if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
          flags[key] = argv[++i]
        } else {
          flags[key] = 'true'
        }
      }
    }
  }

  return { command, flags }
}

// ── I/O helpers ───────────────────────────────────────────────────────────

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf-8')
}

function printJson(data: unknown): void {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n')
}

function printText(text: string): void {
  process.stdout.write(text + '\n')
}

function exit(code: number, message?: string): never {
  if (message) {
    process.stderr.write(`harpocrates: ${message}\n`)
  }
  process.exit(code)
}

// ── Main dispatcher ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const { command, flags } = parseArgs(args)

  switch (command) {
    case 'verify':
      return await handleVerify(flags)
    case 'manifest':
      return await handleManifest(flags)
    case 'hash':
      return await handleHash(flags)
    case 'help':
    default:
      return printHelp()
  }
}

async function handleVerify(flags: Record<string, string>): Promise<void> {
  const contractId = flags['contract-id'] || flags.contractId
  const manifestPath = flags.manifest || flags.m
  const txHash = flags['tx-hash'] || flags.txHash
  const rpcUrl = flags['rpc-url'] || flags.rpcUrl
  const sourceAddress = flags['source-address'] || flags.sourceAddress || process.env.HARPOCRATES_SOURCE_ADDRESS
  const outputFormat = flags.output || flags.o || 'text'
  const offline = flags.offline === 'true'

  if (!contractId) {
    exit(2, '--contract-id is required for verification')
  }

  // ── Read manifest (file, stdin, or flag-constructed) ──────────────────
  let manifestInput: {
    proofId: string
    tier: string
    network: string
    contractId: string
    transactionRef: string
    videoHash: string
    metadataHash: string
    sourceHash: string
    timestamp: string
  }

  if (manifestPath === '-') {
    const raw = await readStdin()
    manifestInput = parseManifest(raw)
  } else if (manifestPath) {
    const raw = await readFile(manifestPath, 'utf-8')
    manifestInput = parseManifest(raw)
  } else if (txHash) {
    exit(2, '--tx-hash requires --manifest for full verification metadata')
  } else {
    exit(2, 'Either --manifest or --tx-hash is required for verification')
  }

  const manifest = createProofManifest(manifestInput)
  let receipt: VerificationReceipt

  if (offline) {
    receipt = createReceipt(
      manifest,
      { status: 'pending', txHash: manifestInput.transactionRef },
      null,
      'pending',
    )
  } else {
    try {
      const txVerification = txHash
        ? await verifyTransaction(txHash, contractId, { rpcUrl, sourceAddress })
        : { status: 'missing' as const, txHash: manifestInput.transactionRef }

      const chainRecord = await lookupByVideoHash(contractId, manifestInput.videoHash, {
        rpcUrl,
        sourceAddress,
      })

      const result = computeResult(chainRecord, txVerification.status)
      receipt = createReceipt(manifest, txVerification, chainRecord, result)
    } catch (err) {
      exit(4, `Verification failed: ${(err as Error).message}`)
    }
  }

  if (outputFormat === 'json') {
    printJson(receipt)
  } else {
    printText(formatReceipt(receipt))
  }

  const exitCodes: Record<string, number> = {
    valid: 0,
    expired: 1,
    revoked: 2,
    not_found: 3,
    network_mismatch: 4,
    contract_mismatch: 5,
    pending: 6,
    failed: 7,
    error: 8,
  }
  exit(exitCodes[receipt.result] ?? 8)
}

async function handleManifest(flags: Record<string, string>): Promise<void> {
  const inputPath = flags.input || flags.i
  const outputPath = flags.output || flags.o
  const outputFormat = flags.format || 'json'

  if (!inputPath) {
    exit(2, '--input is required for manifest creation')
  }

  let metadata: HarpocratesMetadata
  try {
    let raw: string
    if (inputPath === '-') {
      raw = await readStdin()
    } else {
      raw = await readFile(inputPath, 'utf-8')
    }
    const parsed = JSON.parse(raw)
    metadata = validateMetadata(parsed)
  } catch (err) {
    exit(3, `Failed to read or validate metadata: ${(err as Error).message}`)
  }

  if (!flags['tx-hash'] && !flags.txHash) {
    exit(2, '--tx-hash is required for manifest creation')
  }
  if (!flags['contract-id'] && !flags.contractId) {
    exit(2, '--contract-id is required for manifest creation')
  }

  const manifest = createProofManifest({
    proofId: metadata.proofId,
    tier: metadata.tier,
    network: flags.network || 'Test SDF Network ; September 2015',
    contractId: flags['contract-id'] || flags.contractId,
    transactionRef: flags['tx-hash'] || flags.txHash,
    videoHash: flags['video-hash'] || flags.videoHash || '',
    metadataHash: canonicalMetadataHash(metadata),
    sourceHash: metadata.sourceHash,
    timestamp: metadata.timestamp,
  })

  const serialized = serializeManifest(manifest)

  if (outputPath) {
    await writeFile(outputPath, serialized, 'utf-8')
    printText(`Manifest written to ${outputPath}`)
  } else {
    if (outputFormat === 'text') {
      printText(serialized)
    } else {
      printJson(JSON.parse(serialized))
    }
  }
}

async function handleHash(flags: Record<string, string>): Promise<void> {
  const filePath = flags.file || flags.f

  if (!filePath) {
    exit(2, '--file is required for hashing')
  }

  try {
    let hash: string
    if (filePath === '-') {
      const data = await readStdin()
      hash = sha256(data)
    } else {
      hash = await fileHash(filePath)
    }

    printJson({
      algorithm: 'sha256',
      input: filePath === '-' ? 'stdin' : filePath,
      hash,
    })
  } catch (err) {
    exit(3, `Hashing failed: ${(err as Error).message}`)
  }
}

function printHelp(): void {
  const help = `
Harpocrates CLI – headless verification and proof utilities

Usage:
  harpocrates <command> [options]

Commands:
  verify    Verify a proof against the Stellar network.
  manifest  Create a proof manifest from metadata.
  hash      Compute the SHA-256 hash of a file.
  help      Show this help message.

Verify options:
  --contract-id     Contract ID on Stellar (required).
  --manifest        Path to a proof manifest JSON file (use "-" for stdin).
  --tx-hash         Transaction hash to verify on-chain.
  --rpc-url         Stellar RPC URL (default: testnet).
  --source-address  Source address for simulation.
  --output, -o      Output format: "text" (default) or "json".
  --offline         Skip on-chain lookup; validate locally only.

Manifest options:
  --input, -i       Path to metadata JSON file (use "-" for stdin; required).
  --tx-hash         Transaction hash from the registration (required).
  --contract-id     Contract ID on Stellar (required).
  --video-hash      32-byte hex video hash.
  --network         Network passphrase (default: testnet).
  --output, -o      File path to write the manifest to.
  --format          Output format when printing to stdout: "json" (default) or "text".

Hash options:
  --file, -f        Path to the file to hash (use "-" for stdin; required).

Environment variables:
  HARPOCRATES_SOURCE_ADDRESS   Source address for Stellar simulation.
  HARPOCRATES_RPC_URL          Stellar RPC URL (overrides --rpc-url).

Exit codes:
  0   valid
  1   expired
  2   revoked
  3   not_found / missing
  4   network_mismatch
  5   contract_mismatch
  6   pending
  7   failed
  8   error
`
  printText(help.trim())
  process.exit(0)
}

main().catch((err) => {
  process.stderr.write(`harpocrates: ${(err as Error).message}\n`)
  process.exit(8)
})
