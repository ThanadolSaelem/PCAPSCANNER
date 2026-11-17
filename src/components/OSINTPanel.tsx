import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type {
  IOCCandidate,
  OSINTCapabilities,
  OSINTCandidatesResponse,
  OSINTLookupResponse,
  OSINTProviderId,
  PcapApiClient,
} from "../api/client";

type Props = {
  api: PcapApiClient;
  analysisId: string;
  live: boolean;
  connected: boolean;
  initialResult?: OSINTLookupResponse | { state: "not_requested"; results: [] };
  onOpenEvidence: (evidenceId: string) => void;
};

const providerOrder: OSINTProviderId[] = ["virustotal", "abuseipdb", "greynoise", "shodan", "otx"];
const providerNames: Record<OSINTProviderId, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  greynoise: "GreyNoise",
  shodan: "Shodan",
  otx: "AlienVault OTX",
};
const uncertainProviderStates = new Set([
  "provider_timeout", "operation_timeout", "provider_error", "invalid_provider_response", "response_too_large", "redirect_blocked",
]);

function newOperationId(): string {
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi.randomUUID === "function") {
    return cryptoApi.randomUUID().replaceAll("-", "").toLowerCase();
  }
  const bytes = new Uint8Array(16);
  cryptoApi.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function providerState(state: string): string {
  const labels: Record<string, string> = {
    ready: "Ready",
    disabled_by_operator: "Disabled by administrator",
    terms_ack_required: "License / terms acknowledgment required",
    api_key_missing: "API key not configured",
    query_log_redaction_ack_required: "Shodan key log-redaction acknowledgment required",
  };
  return labels[state] ?? state;
}

export default function OSINTPanel({ api, analysisId, live, connected, initialResult, onOpenEvidence }: Props) {
  const [capabilities, setCapabilities] = useState<OSINTCapabilities | null>(null);
  const [candidates, setCandidates] = useState<IOCCandidate[]>([]);
  const [unresolvedOperation, setUnresolvedOperation] = useState<OSINTCandidatesResponse["pending_operation"]>(null);
  const [selectedCandidates, setSelectedCandidates] = useState<string[]>([]);
  const [selectedProviders, setSelectedProviders] = useState<OSINTProviderId[]>([]);
  const [consent, setConsent] = useState(false);
  const [acceptRetryRisk, setAcceptRetryRisk] = useState(false);
  const [pending, setPending] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusRefreshing, setStatusRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<OSINTLookupResponse | null>(null);
  const activeAnalysis = useRef(analysisId);
  const pendingOperationId = useRef<string | null>(null);

  useEffect(() => {
    activeAnalysis.current = analysisId;
    pendingOperationId.current = null;
    setCapabilities(null);
    setCandidates([]);
    setUnresolvedOperation(null);
    setSelectedCandidates([]);
    setSelectedProviders([]);
    setConsent(false);
    setAcceptRetryRisk(false);
    setPending(false);
    setError("");
    setResult(initialResult && initialResult.state !== "not_requested" ? initialResult : null);
    if (!live || !connected) return;
    let current = true;
    setLoading(true);
    Promise.all([api.getOSINTCapabilities(), api.getOSINTCandidates(analysisId)])
      .then(([caps, candidateResponse]) => {
        if (!current || activeAnalysis.current !== analysisId) return;
        setCapabilities(caps);
        setCandidates(candidateResponse.candidates);
        setUnresolvedOperation(candidateResponse.pending_operation ?? null);
      })
      .catch((cause: unknown) => {
        if (current && activeAnalysis.current === analysisId) {
          setError(cause instanceof Error ? cause.message.slice(0, 180) : "osint_load_failed");
        }
      })
      .finally(() => {
        if (current && activeAnalysis.current === analysisId) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [analysisId, api, connected, initialResult, live]);

  const candidateById = useMemo(() => new Map(candidates.map((candidate) => [candidate.candidate_id, candidate])), [candidates]);
  const canSubmit = Boolean(
    live && connected && capabilities?.enabled && selectedCandidates.length > 0 &&
    selectedProviders.length > 0 && consent && (!unresolvedOperation || acceptRetryRisk) && !pending && !loading,
  );

  const refreshOperationState = async (target: string) => {
    setStatusRefreshing(true);
    try {
      const [candidateResponse, report] = await Promise.all([
        api.getOSINTCandidates(target),
        api.getReport(target),
      ]);
      if (activeAnalysis.current !== target) return;
      setCandidates(candidateResponse.candidates);
      setUnresolvedOperation(candidateResponse.pending_operation ?? null);
      const storedResult = report.osint;
      setResult(storedResult && storedResult.state !== "not_requested" ? storedResult : null);
      setAcceptRetryRisk(false);
    } catch (cause) {
      if (activeAnalysis.current === target) {
        setError(cause instanceof Error ? cause.message.slice(0, 180) : "osint_status_refresh_failed");
      }
    } finally {
      if (activeAnalysis.current === target) setStatusRefreshing(false);
    }
  };

  const toggleCandidate = (candidateId: string) => {
    setError("");
    setConsent(false);
    setAcceptRetryRisk(false);
    pendingOperationId.current = null;
    setSelectedCandidates((current) => {
      if (current.includes(candidateId)) return current.filter((item) => item !== candidateId);
      if (current.length >= (capabilities?.max_iocs_per_operation ?? 12)) {
        setError(`เลือกได้ไม่เกิน ${capabilities?.max_iocs_per_operation ?? 12} indicators ต่อ operation`);
        return current;
      }
      return [...current, candidateId];
    });
  };

  const toggleProvider = (provider: OSINTProviderId) => {
    setSelectedProviders((current) => current.includes(provider)
      ? current.filter((item) => item !== provider)
      : [...current, provider]);
    setConsent(false);
    setAcceptRetryRisk(false);
    pendingOperationId.current = null;
    setError("");
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!consent) {
      setError("Confirm the external-sharing consent for this lookup operation.");
      return;
    }
    if (unresolvedOperation && !acceptRetryRisk) {
      setError("Review and explicitly accept the possible duplicate provider charge before starting a new operation.");
      return;
    }
    if (!selectedCandidates.length || !selectedProviders.length || pending) return;
    const target = analysisId;
    const operationId = unresolvedOperation ? newOperationId() : pendingOperationId.current ?? newOperationId();
    pendingOperationId.current = operationId;
    setConsent(false);
    setAcceptRetryRisk(false);
    setPending(true);
    setError("");
    try {
      const response = await api.runOSINTLookup(target, {
        operation_id: operationId,
        candidate_ids: selectedCandidates,
        providers: selectedProviders,
        consent: true,
        accept_uncertain_retry_risk: Boolean(unresolvedOperation && acceptRetryRisk),
      });
      if (activeAnalysis.current !== target) return;
      pendingOperationId.current = null;
      setResult(response);
      setConsent(false);
      setUnresolvedOperation(response.results.some((item) => uncertainProviderStates.has(item.state)) ? {
        operation_id: response.operation_id ?? operationId,
        requested_at: response.requested_at ?? new Date().toISOString(),
        providers: response.provider_ids ?? selectedProviders,
        indicator_count: response.indicator_count ?? selectedCandidates.length,
        state: "uncertain",
      } : null);
    } catch (cause) {
      if (activeAnalysis.current === target) {
        setError(cause instanceof Error ? cause.message.slice(0, 180) : "osint_lookup_failed");
        await refreshOperationState(target);
      }
    } finally {
      if (activeAnalysis.current === target) setPending(false);
    }
  };

  return (
    <div className="report-section osint-panel" id="report-osint">
      <span className="section-kicker">05 / CONSENT-GATED OSINT ENRICHMENT</span>
      <h3>Reputation lookups for selected indicators</h3>
      {!live ? (
        <p className="muted">External reputation lookup is available only for an analysis stored by the connected backend.</p>
      ) : !connected ? (
        <p className="muted">Connect the authenticated backend to inspect its provider configuration.</p>
      ) : loading ? (
        <p className="muted" role="status">Loading local indicator candidates and provider readiness…</p>
      ) : (
        <>
          <p className="osint-disclosure">
            This section performs no lookup until you submit this form. Only the selected normalized public IP/domain or selected artifact hash is disclosed to the chosen provider; no PCAP, packet payload, URI/path, credentials or raw logs are sent. Provider terms, retention and sharing practices apply. Results are third-party context, not proof of compromise, and are excluded from AI report/chat context.
          </p>
          {unresolvedOperation && (
            <div className="osint-state osint-warning" role="alert">
              A previous lookup on this analysis has an uncertain outcome ({unresolvedOperation.providers.join(", ")}, {unresolvedOperation.indicator_count} indicator(s), {unresolvedOperation.requested_at}). Check provider request logs before proceeding; the panel will not automatically retry it.
              <div><button className="secondary-button" type="button" disabled={statusRefreshing || pending} onClick={() => void refreshOperationState(analysisId)}>{statusRefreshing ? "Checking status…" : "Refresh provider status"}</button></div>
            </div>
          )}
          {!capabilities?.enabled && <div className="osint-state osint-unavailable">OSINT network lookup is disabled by the server administrator (PCAP_OSINT_ENABLED=0).</div>}
          {capabilities?.enabled && !capabilities.available && (
            <div className="osint-state osint-unavailable">No provider is ready. Configure a server-side API key and the provider-specific license/terms acknowledgment; secrets are never shown in this UI.</div>
          )}
          {capabilities?.enabled && capabilities.available && (
            <form className="osint-form" onSubmit={(event) => void submit(event)}>
              <fieldset disabled={pending}>
                <legend>Providers — no query is sent until consent and submit</legend>
                <div className="osint-provider-grid">
                  {providerOrder.map((provider) => {
                    const capability = capabilities.providers.find((item) => item.id === provider);
                    if (!capability) return null;
                    return (
                      <div className={`osint-provider ${capability.ready ? "" : "osint-provider-disabled"}`} key={provider}>
                        <input
                          id={`osint-provider-${provider}`}
                          type="checkbox"
                          aria-label={`Select ${providerNames[provider]}`}
                          checked={selectedProviders.includes(provider)}
                          disabled={!capability.ready}
                          onChange={() => toggleProvider(provider)}
                        />
                        <span>
                          <label htmlFor={`osint-provider-${provider}`}>
                            <strong>{providerNames[provider]}</strong>
                            <small>{providerState(capability.state)}</small>
                          </label>
                          <a href={capability.reference} target="_blank" rel="noreferrer">API / terms reference</a>
                        </span>
                      </div>
                    );
                  })}
                </div>
              </fieldset>

              {selectedProviders.includes("virustotal") && (
                <div className="osint-state osint-warning">
                  VirusTotal disclosure: queried indicators may be added to its dataset and made available to the community. Do not submit sensitive, private or confidential indicators. PCAPSCANNER requires an appropriately licensed Premium API acknowledgment; the Public API is not authorized for report-only enrichment.
                </div>
              )}
              {selectedProviders.includes("shodan") && (
                  <div className="osint-state osint-warning">Shodan's documented API key is a query parameter. PCAPSCANNER redacts it from built-in HTTP client logs; deployment proxies, traces, gateways and other request logs must also redact query parameters. Enabling Shodan requires an explicit server-operator attestation.</div>
              )}
              {selectedProviders.includes("greynoise") && (
                <div className="osint-state osint-warning">GreyNoise results are not supplied to AI; its terms prohibit using its data to train or improve AI/ML systems.</div>
              )}

              <div className="osint-candidate-head">
                <strong>Indicators observed in this analysis</strong>
                <span className="mono">{selectedCandidates.length}/{capabilities.max_iocs_per_operation} selected · {candidates.length} candidates</span>
              </div>
              {candidates.length === 0 ? (
                <p className="muted">No public IP, public FQDN or artifact hash was found in the selected structured evidence. Private/reserved identifiers are excluded.</p>
              ) : (
                <div className="osint-candidate-list">
                  {candidates.map((candidate) => (
                    <div className="osint-candidate" key={candidate.candidate_id}>
                      <input
                        type="checkbox"
                        checked={selectedCandidates.includes(candidate.candidate_id)}
                        onChange={() => toggleCandidate(candidate.candidate_id)}
                        disabled={pending}
                      />
                      <span className="mono">{candidate.indicator}</span>
                      <small>{candidate.indicator_type}</small>
                      <span className="osint-evidence-links">
                        {candidate.evidence_ids.slice(0, 4).map((id) => (
                          <button type="button" className="inline-ev-btn" key={id} onClick={() => onOpenEvidence(id)}>{id}</button>
                        ))}
                        {candidate.evidence_ids.length > 4 && <small>+{candidate.evidence_ids.length - 4}</small>}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              <label className="osint-consent">
                <input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} disabled={pending} />
                I authorize sending only the selected indicators to the selected providers for this operation, and have verified the applicable provider license, privacy and retention terms.
              </label>
              {unresolvedOperation && (
                <label className="osint-consent osint-risk-consent">
                  <input type="checkbox" checked={acceptRetryRisk} onChange={(event) => setAcceptRetryRisk(event.target.checked)} disabled={pending} />
                  I checked provider request logs and explicitly authorize a new operation, understanding the previous request may already have been processed or billed.
                </label>
              )}
              {error && <p role="alert" className="osint-error">{error}</p>}
              <button className="primary-button" type="submit" disabled={!canSubmit}>
                {pending ? "Looking up selected indicators…" : `Run ${selectedCandidates.length} × ${selectedProviders.length} bounded lookups`}
              </button>
            </form>
          )}
          {result && (
            <div className="osint-results" aria-live="polite">
              <div className="osint-results-head">
                <strong>Latest operation: {result.state.toUpperCase()}</strong>
                <span className="mono">{result.requested_at ?? ""} · {result.elapsed_ms ?? 0} ms</span>
              </div>
              {result.error_code && <p className="osint-error">{result.error_code}</p>}
              <div className="osint-result-list">
                {result.results.map((item, index) => {
                  const candidate = candidateById.get(item.candidate_id);
                  return (
                    <article className="osint-result" key={`${item.provider}-${item.candidate_id}-${index}`}>
                      <div>
                        <strong>{providerNames[item.provider] ?? item.provider}</strong>
                        <span className="mono">{candidate?.indicator ?? item.indicator_type}</span>
                        <small>{item.state.replaceAll("_", " ")}</small>
                      </div>
                      <dl>
                        {Object.entries(item.summary).map(([key, value]) => (
                          <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd className="mono">{Array.isArray(value) ? value.join(", ") : String(value)}</dd></div>
                        ))}
                      </dl>
                      <a href={item.source_reference} target="_blank" rel="noreferrer">Provider API reference</a>
                      {item.retry_after_seconds !== undefined && <small>Retry guidance: {item.retry_after_seconds}s; no automatic retry was attempted.</small>}
                    </article>
                  );
                })}
              </div>
              <small>Provider outputs are minimized allowlisted summaries. Missing/not-found results do not mean the indicator or capture is benign.</small>
            </div>
          )}
        </>
      )}
    </div>
  );
}
