import { Shield } from 'lucide-react'

type Props = {
  onOpenStudio: () => void
  onOpenVerify: () => void
}

export function LandingView({ onOpenStudio, onOpenVerify }: Props) {
  return (
    <>
      <section className="hero-band">
        <div className="hero-copy">
          <h1>Evidence integrity for silent witnesses.</h1>
          <p className="lede">
            Steganographic video, Noir privacy proofs, Stellar registry — one verifiable chain of
            custody.
          </p>
          <div className="hero-actions">
            <button className="hero-primary" type="button" onClick={onOpenStudio}>
              Begin evidence flow
            </button>
            <button className="hero-secondary" type="button" onClick={onOpenVerify}>
              Verify an artifact
            </button>
          </div>
        </div>
        <div className="signal-panel" aria-label="Protocol status">
          <span>Integrity</span>
          <strong>SHA-256</strong>
          <span>Privacy</span>
          <strong>3 tiers</strong>
          <span>Registry</span>
          <strong>Soroban</strong>
        </div>
      </section>

      <section className="tech-strip">
        <dl className="tech-specs" aria-label="Technical specification">
          <div>
            <dt>Proof system</dt>
            <dd>Noir UltraHonk</dd>
          </div>
          <div>
            <dt>Hash commitment</dt>
            <dd>SHA-256</dd>
          </div>
          <div>
            <dt>On-chain registry</dt>
            <dd>Soroban</dd>
          </div>
          <div>
            <dt>Identity tiers</dt>
            <dd>3 levels</dd>
          </div>
        </dl>
      </section>

      <section className="workflow-band" id="workflow">
        <div className="workflow-heading">
          <h2>How it works</h2>
          <p>From raw video to chain-verifiable evidence in four steps.</p>
        </div>
        <div className="workflow-diagram" aria-label="Harpocrates protocol workflow">
          <svg viewBox="0 0 1120 240" role="img" preserveAspectRatio="xMidYMid meet">
            <defs>
              <marker
                id="flowArrow"
                viewBox="0 0 10 10"
                refX="7"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M0 0 L10 5 L0 10 z" fill="rgba(255,255,255,0.4)" />
              </marker>
            </defs>

            <line
              className="flow-connector"
              x1="280"
              y1="120"
              x2="320"
              y2="120"
              markerEnd="url(#flowArrow)"
            />
            <line
              className="flow-connector"
              x1="560"
              y1="120"
              x2="600"
              y2="120"
              markerEnd="url(#flowArrow)"
            />
            <line
              className="flow-connector"
              x1="840"
              y1="120"
              x2="880"
              y2="120"
              markerEnd="url(#flowArrow)"
            />

            <g className="diagram-node" transform="translate(40 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">
                01
              </text>
              <text className="node-title" x="24" y="40">
                Video
              </text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">
                Steganography
              </text>
              <text className="node-sub" x="24" y="104">
                SHA-256
              </text>
            </g>
            <g className="diagram-node" transform="translate(320 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">
                02
              </text>
              <text className="node-title" x="24" y="40">
                Browser
              </text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">
                Noir Proof
              </text>
              <text className="node-sub" x="24" y="104">
                Nullifier
              </text>
            </g>
            <g className="diagram-node" transform="translate(600 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">
                03
              </text>
              <text className="node-title" x="24" y="40">
                Soroban
              </text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">
                Verifier
              </text>
              <text className="node-sub" x="24" y="104">
                Registry
              </text>
            </g>
            <g className="diagram-node" transform="translate(880 60)">
              <rect width="240" height="120" rx="10" />
              <text className="node-step" x="216" y="34">
                04
              </text>
              <text className="node-title" x="24" y="40">
                Portal
              </text>
              <line className="node-divider" x1="24" y1="58" x2="216" y2="58" />
              <text className="node-sub" x="24" y="82">
                Extract
              </text>
              <text className="node-sub" x="24" y="104">
                Confirm
              </text>
            </g>
          </svg>
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Shield size={16} aria-hidden="true" />
            <span>Harpocrates</span>
          </div>
          <p className="footer-tagline">Privacy-first evidence integrity on Stellar.</p>
          <div className="footer-stack">
            <span>Noir ZK</span>
            <span>SHA-256</span>
            <span>Soroban</span>
          </div>
        </div>
      </footer>
    </>
  )
}
