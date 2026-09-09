import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Shield, RotateCcw } from 'lucide-react'
import './ErrorBoundary.css'

type ErrorBoundaryProps = {
  children: ReactNode
}

type ErrorBoundaryState = {
  hasError: boolean
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(_error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', _error.message, info.componentStack)
  }

  handleReset = () => {
    this.setState({ hasError: false })
  }

  handleRetry = () => {
    this.setState({ hasError: false })
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary-overlay">
          <div className="error-boundary-card">
            <Shield size={32} aria-hidden="true" className="error-boundary-icon" />
            <h2 className="error-boundary-title">Something went wrong</h2>
            <p className="error-boundary-message">
              The evidence workflow encountered an unexpected error. No data has been compromised.
            </p>
            <div className="error-boundary-actions">
              <button className="error-boundary-btn error-boundary-btn-primary" type="button" onClick={this.handleRetry}>
                <RotateCcw size={14} aria-hidden="true" />
                Reload
              </button>
              <button className="error-boundary-btn error-boundary-btn-secondary" type="button" onClick={this.handleReset}>
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
