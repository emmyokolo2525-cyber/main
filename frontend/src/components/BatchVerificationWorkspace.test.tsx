import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import BatchVerificationWorkspace from './BatchVerificationWorkspace'

describe('BatchVerificationWorkspace UI Component', () => {
  it('renders idle workspace header and dropzone', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    expect(screen.getByRole('heading', { level: 2, name: /Evidence Batch Verification Workspace/i })).toBeInTheDocument()
    expect(screen.getByText(/Drop evidence files or standalone JSON receipts/i)).toBeInTheDocument()
  })

  it('toggles pool settings configuration panel', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const toggleBtn = screen.getByRole('button', { name: /Pool Settings/i })
    fireEvent.click(toggleBtn)

    expect(screen.getByLabelText(/Concurrency \(Workers: 1-8\)/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Max Per-File Limit \(MB\)/i)).toBeInTheDocument()
  })

  it('handles adding files to workspace queue', async () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const file1 = new File(['evidence sample content'], 'evidence1.mp4', { type: 'video/mp4' })
    const input = screen.getByLabelText(/Drop evidence files or standalone JSON receipts/i) as HTMLInputElement

    fireEvent.change(input, { target: { files: [file1] } })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Verify Batch \(1\)/i })).toBeInTheDocument()
      expect(screen.getByText('evidence1.mp4')).toBeInTheDocument()
    })
  })
})
