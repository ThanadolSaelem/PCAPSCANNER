/**
 * Session-scoped deterministic pseudonymization for documentation screenshots and exports.
 * Maps IPv4/IPv6 addresses, domains, and SHA/MD5/JA3 hashes to consistent synthetic labels
 * (`HOST-01`, `DOMAIN-01.example`, `HASH-01`) within the active session, without ever
 * exporting or persisting a reverse lookup table.
 */

export class PrivacyRedactor {
  private readonly enabled: boolean;
  private readonly ipMap = new Map<string, string>();
  private readonly domainMap = new Map<string, string>();
  private readonly hashMap = new Map<string, string>();

  constructor(enabled: boolean) {
    this.enabled = enabled;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  redactIp(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim();
    const portSplit = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$/);
    if (portSplit) {
      const ip = portSplit[1]!;
      const port = portSplit[2] ?? "";
      let alias = this.ipMap.get(ip);
      if (!alias) {
        alias = `HOST-${String(this.ipMap.size + 1).padStart(2, "0")}`;
        this.ipMap.set(ip, alias);
      }
      return `${alias}${port}`;
    }
    let alias = this.ipMap.get(raw);
    if (!alias) {
      alias = `HOST-${String(this.ipMap.size + 1).padStart(2, "0")}`;
      this.ipMap.set(raw, alias);
    }
    return alias;
  }

  redactDomain(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim().toLowerCase();
    let alias = this.domainMap.get(raw);
    if (!alias) {
      alias = `domain-${String(this.domainMap.size + 1).padStart(2, "0")}.example`;
      this.domainMap.set(raw, alias);
    }
    return alias;
  }

  redactHash(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    const raw = value.trim().toLowerCase();
    let alias = this.hashMap.get(raw);
    if (!alias) {
      alias = `HASH-${String(this.hashMap.size + 1).padStart(2, "0")}`;
      this.hashMap.set(raw, alias);
    }
    return alias;
  }

  redactEndpoint(value: string): string {
    if (!this.enabled || !value || value === "—") return value;
    if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(value.trim())) {
      return this.redactIp(value);
    }
    if (value.includes(".") && !value.includes(" ")) {
      return this.redactDomain(value);
    }
    return this.redactFreeText(value);
  }

  redactFreeText(text: string): string {
    if (!this.enabled || !text) return text;
    let out = text.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?\b/g, (_m, ip: string, port?: string) =>
      this.redactIp(`${ip}${port ?? ""}`),
    );
    out = out.replace(/\b[a-f0-9]{32,64}\b/gi, (hash) => this.redactHash(hash));
    return out;
  }
}
