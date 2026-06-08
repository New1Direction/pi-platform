// Turn an internal agent class name into a human-readable title.
// e.g. "PiGitSecScanner" → "Git Security Scanner", "PiLLMHallucinationDetector"
//      → "LLM Hallucination Detector", "PiERC4626VaultGuard" → "ERC4626 Vault Guard".

const ACRONYMS: Record<string, string> = {
  Sec: 'Security',
  Llm: 'LLM', Erc: 'ERC', Eip: 'EIP', Zk: 'ZK', Api: 'API', Sql: 'SQL',
  Dos: 'DoS', Mev: 'MEV', Defi: 'DeFi', Tdd: 'TDD', Rbac: 'RBAC', Jwt: 'JWT',
  Ssh: 'SSH', Iac: 'IaC', Sbom: 'SBOM', Pci: 'PCI', Dss: 'DSS', Hipaa: 'HIPAA',
  Grpc: 'gRPC', Cpi: 'CPI', Ast: 'AST', Evm: 'EVM', Eoa: 'EOA', Twap: 'TWAP',
  Amm: 'AMM', Cors: 'CORS', Csrf: 'CSRF', Xss: 'XSS', Ssrf: 'SSRF', K8s: 'K8s',
  Yul: 'Yul', Vyper: 'Vyper', Solana: 'Solana', Circom: 'Circom',
};

export function humanizeAgentName(agentName: string): string {
  if (!agentName) return 'Agent';
  // Drop the Pi prefix, split camelCase and letter/number boundaries.
  const stripped = agentName.replace(/^Pi/, '');
  const spaced = stripped
    .replace(/([a-z])([A-Z])/g, '$1 $2')        // gitSec → git Sec
    .replace(/([A-Z]{2,})([A-Z][a-z])/g, '$1 $2') // LLMHall → LLM Hall
    .replace(/(\d)([A-Z][a-z])/g, '$1 $2');      // ERC4626Vault → ERC4626 Vault (keeps ERC4626 intact)

  return spaced
    .split(/\s+/)
    .filter(Boolean)
    .map(w => ACRONYMS[w] ?? (/^[A-Z0-9]+$/.test(w) ? w : w))
    .join(' ')
    .trim() || agentName;
}
