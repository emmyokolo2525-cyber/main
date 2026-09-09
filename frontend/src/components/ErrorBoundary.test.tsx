import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import ErrorBoundary from './ErrorBoundary'

function Bomb({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) throw new Error('💥')
  return <p>child ok</p>
}

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ErrorBoundary', () => {
  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <p>hello</p>
      </ErrorBoundary>,
    )
    expect(screen.getByText('hello')).toBeInTheDocument()
  })

  it('renders fallback UI when a child throws', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    expect(screen.getByText('The evidence workflow encountered an unexpected error. No data has been compromised.')).toBeInTheDocument()
  })

  it('provides a dismiss button that resets error state and re-attempts render', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>,
    )
    const dismiss = screen.getByText('Dismiss')
    expect(dismiss).toBeInTheDocument()
    fireEvent.click(dismiss)
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('provides a reload button', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('Reload')).toBeInTheDocument()
  })

  it('does not expose stack traces or proof data', () => {
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>,
    )
    expect(screen.queryByText(/Error:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/stack/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/proof/i)).not.toBeInTheDocument()
  })

  it('recovers when the error is cleared and re-renders children', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <Bomb shouldThrow={true} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    rerender(
      <ErrorBoundary>
        <Bomb shouldThrow={false} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Dismiss'))
    expect(screen.getByText('child ok')).toBeInTheDocument()
  })
})
