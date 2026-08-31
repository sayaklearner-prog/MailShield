"use client";

import { useState, useEffect } from "react";
import {
  useIntelligenceStore,
  EnrichedIndicator,
  ReputationVerdict,
} from "@/lib/intelligence-store";
import { useNetworkStore, NetworkIntelligence } from "@/lib/network-store";
import { useURLIntelligenceStore, URLAnalysisResult } from "@/lib/url-intelligence-store";
import { UrlDetailDrawer } from "@/components/security/UrlDetailDrawer";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  Globe,
  Radio,
  Search,
  ExternalLink,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  Layers,
  Sparkles,
  Link as LinkIcon,
  Database,
  CheckCircle2,
  Clock,
  Fingerprint,
  MapPin,
  Server,
  Network,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";

export default function ThreatIntelligencePage() {
  const {
    enrichedIndicators,
    providerStatuses,
    enrichIndicator,
    fetchProviderStatuses,
    isLoading: isIntelLoading,
  } = useIntelligenceStore();

  const {
    networkRecords,
    enrichIP,
    isLoading: isNetLoading,
  } = useNetworkStore();

  const { urls: urlResults, analyzeUrl, isAnalyzing: isUrlAnalyzing } = useURLIntelligenceStore();

  const [activeView, setActiveView] = useState<"indicators" | "network">("indicators");
  const [queryInput, setQueryInput] = useState("");
  const [queryType, setQueryType] = useState<string>("auto");
  const [selectedVerdict, setSelectedVerdict] = useState<string>("all");
  const [selectedType, setSelectedType] = useState<string>("all");
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedUrlResult, setSelectedUrlResult] = useState<URLAnalysisResult | null>(null);

  useEffect(() => {
    fetchProviderStatuses();
  }, [fetchProviderStatuses]);

  const detectType = (val: string): string => {
    const trimmed = val.trim();
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(trimmed)) return "ip";
    if (/^[a-fA-F0-9]{64}$/.test(trimmed) || /^[a-fA-F0-9]{32}$/.test(trimmed)) return "attachment_hash";
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) return "url";
    if (/^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(trimmed)) return "domain";
    return "domain";
  };

  const handleManualEnrich = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = queryInput.trim();
    if (!clean) return;

    const finalType = queryType === "auto" ? detectType(clean) : queryType;
    toast.info(`Querying intelligence providers for: ${clean}...`);

    if (finalType === "ip") {
      await Promise.all([enrichIndicator(clean, "ip"), enrichIP(clean)]);
      toast.success(`Enrichment complete for IP: ${clean}`);
    } else if (finalType === "url") {
      const [intelRes, urlRes] = await Promise.all([
        enrichIndicator(clean, "url"),
        analyzeUrl(clean),
      ]);
      if (urlRes) {
        setSelectedUrlResult(urlRes);
        toast.success(`URL Analysis complete: Threat Score ${urlRes.threat_score}/100 (${urlRes.severity})`);
      } else if (intelRes) {
        toast.success(`Enrichment complete: Verdict ${intelRes.overall_verdict.toUpperCase()}`);
      } else {
        toast.error("Failed to retrieve URL threat intelligence");
      }
    } else {
      const result = await enrichIndicator(clean, finalType);
      if (result) {
        toast.success(
          `Enrichment complete: Verdict ${result.overall_verdict.toUpperCase()}${
            result.max_reputation_score ? ` (Score: ${result.max_reputation_score}/100)` : ""
          }`
        );
      } else {
        toast.error("Failed to retrieve external threat intelligence");
      }
    }
    setQueryInput("");
  };

  const indicatorsList: EnrichedIndicator[] = Object.values(enrichedIndicators);
  const networkList: NetworkIntelligence[] = Object.values(networkRecords);

  const filteredIndicators = indicatorsList.filter((item) => {
    const matchesSearch = item.indicator.toLowerCase().includes(searchFilter.toLowerCase());
    const matchesVerdict = selectedVerdict === "all" || item.overall_verdict === selectedVerdict;
    const matchesType = selectedType === "all" || item.indicator_type === selectedType;
    return matchesSearch && matchesVerdict && matchesType;
  });

  return (
    <div className="space-y-6 p-6 lg:p-8 max-w-7xl mx-auto h-full overflow-y-auto font-mono">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold">
              Multi-Source Intelligence & Geolocation Layer
            </span>
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight mt-1 text-foreground">
            Threat Intelligence & Network Geolocation
          </h1>
          <p className="text-muted-foreground text-xs mt-0.5">
            Multi-source external threat intelligence (VirusTotal, AbuseIPDB, WHOIS) correlated with passive IP Geolocation and ASN infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-1 bg-card/60 p-1 rounded-lg border border-border/40 text-xs">
          <button
            onClick={() => setActiveView("indicators")}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5",
              activeView === "indicators" ? "bg-cyan-600 text-white shadow-sm" : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Database className="h-3.5 w-3.5" />
            IOC Reputation
          </button>
          <button
            onClick={() => setActiveView("network")}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-colors flex items-center gap-1.5",
              activeView === "network" ? "bg-cyan-600 text-white shadow-sm" : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Globe className="h-3.5 w-3.5" />
            IP Geolocation & ASN ({networkList.length})
          </button>
        </div>
      </div>

      {/* Provider Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {providerStatuses.map((p) => {
          const nameLabel =
            p.provider === "virustotal"
              ? "VirusTotal API v3"
              : p.provider === "abuseipdb"
              ? "AbuseIPDB v2"
              : "WHOIS & RDAP Intel";

          return (
            <Card key={p.provider} className="border-border/40 bg-card/40 backdrop-blur-xl">
              <CardContent className="p-4 flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Radio className={cn("h-3.5 w-3.5", p.configured ? "text-emerald-400" : "text-cyan-400")} />
                    <span className="font-bold text-xs text-foreground">{nameLabel}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    Types: {p.supported_types.join(", ")}
                  </div>
                  <div className="text-[9px] text-muted-foreground/80 mt-1">
                    {p.configured ? "Active & Configured" : "Operational (Core telemetry available)"}
                  </div>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[9px] font-mono uppercase",
                    p.configured ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-muted text-muted-foreground"
                  )}
                >
                  {p.status}
                </Badge>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Interactive IOC / IP Enrichment Console */}
      <Card className="border-border/50 bg-card/50 backdrop-blur-xl">
        <CardHeader className="py-3 px-5 border-b border-border/30">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2 font-mono">
            <Search className="h-4 w-4 text-cyan-400" />
            Query External Threat Intelligence & Geolocation
          </CardTitle>
          <CardDescription className="text-[11px]">
            Query public IPs, domains, URLs, or SHA-256 hashes against configured reputation and ASN providers.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4">
          <form onSubmit={handleManualEnrich} className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1">
              <Input
                placeholder="Enter IP (e.g. 209.85.220.41), domain, URL, or SHA-256..."
                value={queryInput}
                onChange={(e) => setQueryInput(e.target.value)}
                className="bg-background/70 text-xs font-mono h-9"
              />
            </div>

            <select
              value={queryType}
              onChange={(e) => setQueryType(e.target.value)}
              className="h-9 text-xs font-mono bg-background/80 border border-border/40 rounded-md px-3 text-foreground focus:outline-none"
            >
              <option value="auto">Auto-Detect Type</option>
              <option value="ip">IP Address (Geo + ASN)</option>
              <option value="domain">Domain Name</option>
              <option value="url">URL Link</option>
              <option value="attachment_hash">SHA-256 Hash</option>
            </select>

            <Button
              type="submit"
              disabled={isIntelLoading || isNetLoading || !queryInput.trim()}
              className="h-9 bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shrink-0 shadow-md shadow-cyan-600/20"
            >
              <Sparkles className={cn("h-3.5 w-3.5", (isIntelLoading || isNetLoading) && "animate-spin")} />
              Enrich Indicator
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* VIEW 1: IOC Reputation Catalog */}
      {activeView === "indicators" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-foreground">Enriched Threat Indicator Catalog</h2>
              <Badge variant="outline" className="text-[10px] font-mono">
                {filteredIndicators.length} IOCs
              </Badge>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <Input
                placeholder="Filter catalog..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="h-8 text-xs bg-card/40 w-44 font-mono"
              />

              <select
                value={selectedVerdict}
                onChange={(e) => setSelectedVerdict(e.target.value)}
                className="h-8 text-xs font-mono bg-background/80 border border-border/40 rounded px-2 text-foreground"
              >
                <option value="all">All Verdicts</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
                <option value="unknown">Unknown</option>
              </select>

              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="h-8 text-xs font-mono bg-background/80 border border-border/40 rounded px-2 text-foreground"
              >
                <option value="all">All Types</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="attachment_hash">Hash</option>
              </select>
            </div>
          </div>

          {filteredIndicators.length === 0 ? (
            <EmptyState
              icon={Globe}
              title="No Threat Intelligence Records Match Filter"
              description="Extract indicators from ingested emails or query external IOCs using the search bar above."
            />
          ) : (
            <div className="space-y-3">
              {filteredIndicators.map((item) => (
                <Card key={item.indicator} className="border-border/40 bg-card/40">
                  <CardContent className="p-4 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/20 pb-2.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-sm text-foreground break-all">{item.indicator}</span>
                        <Badge variant="outline" className="text-[9px] font-mono uppercase bg-muted/30">
                          {item.indicator_type}
                        </Badge>
                        <SeverityBadge severity={item.overall_verdict} score={item.max_reputation_score} size="sm" />
                      </div>

                      <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground shrink-0">
                        {item.is_private_or_reserved && (
                          <span className="text-[10px] text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                            Private/Reserved Range
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                      {item.results.map((res, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-background/50 border border-border/30 space-y-1.5">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-1.5">
                              <Fingerprint className="h-3.5 w-3.5 text-cyan-400" />
                              <span className="font-bold uppercase font-mono text-[10px] text-foreground">{res.provider}</span>
                            </div>
                            {res.source_url && (
                              <a
                                href={res.source_url}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[9px] text-muted-foreground hover:text-foreground flex items-center gap-0.5 font-mono"
                              >
                                Source <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            )}
                          </div>

                          <div className="text-[11px] text-muted-foreground space-y-0.5">
                            {res.findings.map((f, fi) => (
                              <p key={fi} className="leading-snug">· {f}</p>
                            ))}
                          </div>

                          <div className="flex items-center justify-between text-[9px] font-mono text-muted-foreground/70 pt-1">
                            <span suppressHydrationWarning>Queried: {format(new Date(res.queried_at), "HH:mm:ss")}</span>
                            {res.is_cached && <span className="text-emerald-400">Cached</span>}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* AI/ML API Threat Synthesis */}
                    {item.ai_synthesis && (
                      <div className="mt-3 p-3 rounded-lg bg-purple-500/5 border border-purple-500/20 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono uppercase font-bold text-purple-400 flex items-center gap-1.5">
                            <Sparkles className="h-3 w-3" />
                            AI Threat Synthesis ({item.ai_synthesis.provider_used})
                          </span>
                          <Badge variant="outline" className="text-[9px] font-mono uppercase border-purple-500/30 text-purple-300">
                            {item.ai_synthesis.threat_level}
                          </Badge>
                        </div>
                        <p className="text-xs text-foreground font-medium">{item.ai_synthesis.summary}</p>
                        {item.ai_synthesis.mitre_attack_techniques?.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap pt-1">
                            <span className="text-[10px] text-muted-foreground font-mono">MITRE:</span>
                            {item.ai_synthesis.mitre_attack_techniques.map((t, ti) => (
                              <Badge key={ti} variant="outline" className="text-[9px] font-mono bg-purple-500/10 text-purple-400 border-purple-500/20">
                                {t}
                              </Badge>
                            ))}
                          </div>
                        )}
                        {item.ai_synthesis.recommended_soc_actions?.length > 0 && (
                          <div className="text-[11px] text-muted-foreground pt-1 space-y-0.5 border-t border-purple-500/10">
                            <span className="text-[10px] font-mono font-bold text-purple-400 block">Recommended Actions:</span>
                            {item.ai_synthesis.recommended_soc_actions.map((act, ai) => (
                              <p key={ai} className="leading-tight">· {act}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: IP Geolocation & ASN Intelligence */}
      {activeView === "network" && (
        <div className="space-y-4">
          <div className="rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-3.5 text-xs text-muted-foreground space-y-1">
            <span className="font-bold text-cyan-400 flex items-center gap-1.5">
              <MapPin className="h-3.5 w-3.5" />
              Forensic Principle: Approximate Geolocation ≠ Physical Attacker Location
            </span>
            <p>
              IP geolocation denotes the approximate network routing registration point reported by regional registries and telemetry databases. It does not establish the physical whereabouts of a threat actor.
            </p>
          </div>

          <div className="space-y-3">
            {networkList.map((net) => (
              <Card key={net.ip} className="border-border/40 bg-card/40">
                <CardContent className="p-4 space-y-3 text-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/20 pb-2.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-bold text-sm text-foreground">{net.ip}</span>
                      <Badge variant="outline" className="text-[9px] font-mono uppercase bg-muted/30">
                        {net.ip_version} · {net.category}
                      </Badge>
                      <Badge
                        className={cn(
                          "text-[9px] font-mono uppercase font-bold",
                          net.network_type === "cloud" || net.network_type === "hosting"
                            ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                            : "bg-cyan-500/20 text-cyan-400 border-cyan-500/30"
                        )}
                      >
                        Type: {net.network_type}
                      </Badge>
                    </div>

                    <div className="text-[11px] font-mono text-muted-foreground">
                      Confidence: <strong className="text-foreground">{net.confidence.toUpperCase()}</strong>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* Geolocation Card */}
                    <div className="p-3 rounded-lg bg-background/50 border border-border/30 space-y-1">
                      <span className="text-[10px] font-mono uppercase font-bold text-muted-foreground flex items-center gap-1">
                        <MapPin className="h-3 w-3 text-cyan-400" />
                        Approximate Geolocation
                      </span>
                      {net.geolocation ? (
                        <div className="space-y-0.5 text-[11px] text-muted-foreground">
                          <p className="text-foreground font-semibold">
                            {net.geolocation.city ? `${net.geolocation.city}, ` : ""}
                            {net.geolocation.region ? `${net.geolocation.region}, ` : ""}
                            {net.geolocation.country} ({net.geolocation.country_code})
                          </p>
                          {net.geolocation.latitude && net.geolocation.longitude && (
                            <p className="font-mono text-[10px]">
                              Coords: {net.geolocation.latitude.toFixed(4)}, {net.geolocation.longitude.toFixed(4)}
                              {net.geolocation.timezone ? ` · ${net.geolocation.timezone}` : ""}
                            </p>
                          )}
                          <p className="text-[10px] text-muted-foreground/70">Source: {net.geolocation.source}</p>
                        </div>
                      ) : (
                        <p className="text-muted-foreground italic">
                          {net.is_public ? "No geographic coordinates returned." : "Private/Reserved allocation — lookup omitted."}
                        </p>
                      )}
                    </div>

                    {/* ASN & Network Ownership Card */}
                    <div className="p-3 rounded-lg bg-background/50 border border-border/30 space-y-1">
                      <span className="text-[10px] font-mono uppercase font-bold text-muted-foreground flex items-center gap-1">
                        <Server className="h-3 w-3 text-purple-400" />
                        ASN & Routing Infrastructure
                      </span>
                      {net.asn ? (
                        <div className="space-y-0.5 text-[11px] text-muted-foreground">
                          <p className="text-foreground font-semibold">
                            {net.asn.organization || "Unknown Organization"}
                          </p>
                          <p className="font-mono text-[10px]">
                            {net.asn.asn ? `ASN: ${net.asn.asn}` : "No ASN identifier"}
                            {net.asn.network ? ` · Network: ${net.asn.network}` : ""}
                          </p>
                          <p className="text-[10px] text-muted-foreground/70">Source: {net.asn.source}</p>
                        </div>
                      ) : (
                        <p className="text-muted-foreground italic">
                          {net.is_public ? "ASN metadata unavailable." : "Private/Reserved allocation — lookup omitted."}
                        </p>
                      )}
                    </div>
                  </div>

                  {/* AI/ML API Network & Infrastructure Synthesis */}
                  {net.ai_synthesis && (
                    <div className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase font-bold text-purple-400 flex items-center gap-1.5">
                          <Sparkles className="h-3 w-3" />
                          AI Network & Geopolitical Synthesis ({net.ai_synthesis.provider_used})
                        </span>
                        <Badge variant="outline" className="text-[9px] font-mono uppercase border-purple-500/30 text-purple-300">
                          {net.ai_synthesis.assessment}
                        </Badge>
                      </div>
                      <p className="text-xs text-foreground font-medium">{net.ai_synthesis.summary}</p>
                      {net.ai_synthesis.infrastructure_analysis && (
                        <p className="text-[11px] text-muted-foreground">
                          <strong className="text-purple-400 font-mono text-[10px]">Infrastructure: </strong>
                          {net.ai_synthesis.infrastructure_analysis}
                        </p>
                      )}
                      {net.ai_synthesis.jurisdiction_risk && (
                        <p className="text-[11px] text-muted-foreground">
                          <strong className="text-cyan-400 font-mono text-[10px]">Jurisdiction Risk: </strong>
                          {net.ai_synthesis.jurisdiction_risk}
                        </p>
                      )}
                      {net.ai_synthesis.recommendations?.length > 0 && (
                        <div className="text-[11px] text-muted-foreground pt-1 space-y-0.5 border-t border-purple-500/10">
                          <span className="text-[10px] font-mono font-bold text-purple-400 block">SOC Recommendations:</span>
                          {net.ai_synthesis.recommendations.map((rec, ri) => (
                            <p key={ri} className="leading-tight">· {rec}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* URL Forensic Detail Drawer */}
      <UrlDetailDrawer
        urlResult={selectedUrlResult}
        onClose={() => setSelectedUrlResult(null)}
      />
    </div>
  );
}
