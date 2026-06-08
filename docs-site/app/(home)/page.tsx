import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col">
      {/* Hero */}
      <section className="flex flex-1 flex-col items-center justify-center gap-6 px-6 py-24 text-center">
        <div className="inline-flex items-center gap-2 rounded-full border bg-muted/50 px-4 py-1.5 text-sm text-muted-foreground">
          <span className="h-2 w-2 rounded-full bg-green-500" />
          248 agents · 1,560 tests passing · Production ready
        </div>

        <h1 className="max-w-3xl text-5xl font-bold tracking-tight sm:text-6xl lg:text-7xl">
          The{' '}
          <span className="bg-gradient-to-r from-blue-600 to-violet-600 bg-clip-text text-transparent">
            PI Platform
          </span>
        </h1>

        <p className="max-w-2xl text-lg text-muted-foreground sm:text-xl">
          A governed, deterministic AI agent platform. 248 security micro-agents —
          HIPAA, PCI DSS, MASVS, blockchain, cloud, crypto, container, and more —
          composable into auditable DAG pipelines with cryptographic replay.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4">
          <Link
            href="/docs"
            className="rounded-lg bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
          >
            Read the Docs
          </Link>
          <Link
            href="/docs/getting-started"
            className="rounded-lg border px-6 py-3 text-sm font-medium transition-colors hover:bg-muted"
          >
            Quick Start →
          </Link>
        </div>
      </section>

      {/* Feature grid */}
      <section className="border-t px-6 py-16">
        <div className="mx-auto grid max-w-5xl gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <div key={f.title} className="rounded-xl border bg-card p-6">
              <div className="mb-3 text-2xl">{f.icon}</div>
              <h3 className="mb-2 font-semibold">{f.title}</h3>
              <p className="text-sm text-muted-foreground">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t px-6 py-8 text-center text-sm text-muted-foreground">
        PI Platform · Built with{' '}
        <a href="https://fumadocs.dev" className="underline underline-offset-4">
          Fumadocs
        </a>
      </footer>
    </main>
  );
}

const features = [
  {
    icon: '🔒',
    title: '248 Security Agents',
    desc: 'HIPAA, PCI DSS, MASVS, OWASP, IAM, crypto, containers, blockchain — all composable, all governed.',
  },
  {
    icon: '⚙️',
    title: 'Deterministic Orchestration',
    desc: 'Every execution produces a content-addressed ledger entry. Full replay with cryptographic integrity.',
  },
  {
    icon: '🦀',
    title: 'Rust-Accelerated Core',
    desc: 'PyO3-backed Rust core handles the agent fabric at up to 12.5× Python throughput with GIL-released parallelism.',
  },
  {
    icon: '🧱',
    title: 'WASM Extension Sandbox',
    desc: 'pi-extension-governor backs every agent with Wasmer — capability deny-by-default, gas-metered, fail-closed.',
  },
  {
    icon: '🧩',
    title: 'Composition DAG API',
    desc: 'Submit ExplicitCompositionRequest DAGs. Nodes fan out in parallel or chain sequentially. One ledger ID per run.',
  },
  {
    icon: '📋',
    title: 'Tenant-Scoped Audit Trail',
    desc: 'JWT-authenticated tenant stamping on every write. Per-tenant read scoping. Tamper-evident hash chain.',
  },
];
