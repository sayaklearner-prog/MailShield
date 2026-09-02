"use client";

import { useState, useMemo } from "react";
import { useEmailStore } from "@/lib/email-store";
import { useIntelligenceStore } from "@/lib/intelligence-store";
import { useURLIntelligenceStore, URLAnalysisResult } from "@/lib/url-intelligence-store";
import { UrlDetailDrawer } from "@/components/security/UrlDetailDrawer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Fingerprint,
  Search,
  Link as LinkIcon,
  Globe,
  Radio,
  Mail,
  Paperclip,
  Sparkles,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Network,
  Eye,
} from "lucide-react";
import Link from "next/link";
import { extractForensicsLocally } from "@/lib/forensic-extractor";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ProvenanceBadge } from "@/components/security/ProvenanceBadge";
import { EmptyState } from "@/components/security/EmptyState";
import { SectionHeader } from "@/components/security/SectionHeader";
import { motion } from "framer-motion";

type FilterCategory = "all" | "url" | "domain" | "ip" | "email" | "attachment";

export default function IndicatorsPage() {
  const { emails } = useEmailStore();
  const { enrichedIndicators, enrichBatch, enrichIndicator, isLoading } = useIntelligenceStore();
  const { urls: urlResults, analyzeUrl, isAnalyzing: isUrlAnalyzing } = useURLIntelligenceStore();

  const [filterCategory, setFilterCategory] = useState<FilterCategory>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedUrlResult, setSelectedUrlResult] = useState<URLAnalysisResult | null>(null);

  // Aggregate all extracted artifacts from all ingested emails
  const allArtifacts = useMemo(() => {
    const list: Array<{
      id: string;
      type: "url" | "domain" | "ip" | "email" | "attachment";
      value: string;
      source: string;
      evidenceReference: string;
      emailSubject: string;
      emailId: string;
    }> = [];

    emails.forEach((email) => {
      const forensics =
        email.forensicData ||
        extractForensicsLocally({
          subject: email.subject,
          from: email.fromEmail || email.from,
          body: email.body,
          htmlBody: email.htmlBody,
          headers: email.headers,
          rawHeadersList: email.rawHeadersList,
          attachments: email.attachments,
        });

      // URLs
      forensics.urls.forEach((u, i) => {
        list.push({
          id: `${email.id}-url-${i}`,
          type: "url",
          value: u.url,
          source: u.source,
          evidenceReference: u.evidenceReference,
          emailSubject: email.subject,
          emailId: email.id,
        });
      });

      // Domains
      forensics.domains.forEach((d, i) => {
        list.push({
          id: `${email.id}-domain-${i}`,
          type: "domain",
          value: d.domain,
          source: d.source,
          evidenceReference: d.evidenceReference,
          emailSubject: email.subject,
          emailId: email.id,
        });
      });

      // IPs
      forensics.ipAddresses.forEach((ip, i) => {
        list.push({
          id: `${email.id}-ip-${i}`,
          type: "ip",
          value: ip.ipAddress,
          source: ip.source,
          evidenceReference: ip.evidenceReference,
          emailSubject: email.subject,
          emailId: email.id,
        });
      });

      // Emails
      forensics.emailAddresses.forEach((ea, i) => {
        list.push({
          id: `${email.id}-email-${i}`,
          type: "email",
          value: ea.address,
          source: ea.source,
          evidenceReference: ea.evidenceReference,
          emailSubject: email.subject,
          emailId: email.id,
        });
      });

      // Attachments
      forensics.attachments.forEach((att, i) => {
        list.push({
          id: `${email.id}-att-${i}`,
          type: "attachment",
          value: att.filename,
          source: att.source,
          evidenceReference: att.evidenceReference,
          emailSubject: email.subject,
          emailId: email.id,
        });
      });
    });

    return list;
  }, [emails]);

  const filteredArtifacts = allArtifacts.filter((item) => {
    const matchesCategory = filterCategory === "all" || item.type === filterCategory;
    const matchesQuery =
      searchQuery === "" ||
      item.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.evidenceReference.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.emailSubject.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesQuery;
  });

  const handleBatchEnrichAll = async () => {
    const queryable = allArtifacts
      .filter((a) => a.type === "domain" || a.type === "ip" || a.type === "url")
      .map((a) => ({ value: a.value, type: a.type }));

    if (queryable.length === 0) {
      toast.info("No queryable IOCs (domains, IPs, URLs) extracted yet.");
      return;
    }

    toast.info(`Querying external threat intelligence for ${queryable.length} extracted indicators...`);
    const results = await enrichBatch(queryable);
    toast.success(`Enriched ${results.length} indicators with external threat intelligence.`);
  };

  const getIcon = (type: string) => {
    switch (type) {
      case "url":
        return <LinkIcon className="h-3.5 w-3.5 text-blue-400" />;
      case "domain":
        return <Globe className="h-3.5 w-3.5 text-emerald-400" />;
      case "ip":
        return <Radio className="h-3.5 w-3.5 text-purple-400" />;
      case "email":
        return <Mail className="h-3.5 w-3.5 text-amber-400" />;
      case "attachment":
        return <Paperclip className="h-3.5 w-3.5 text-rose-400" />;
      default:
        return <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  };

  return (
    <div className="space-y-6 p-6 lg:p-8 max-w-6xl mx-auto h-full overflow-y-auto font-mono">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint className="h-5 w-5 text-cyan-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              Forensic Artifact & IOC Inventory
            </h1>
          </div>
          <p className="text-muted-foreground text-xs mt-1">
            Technical indicators extracted from email MIME structures and routing headers with external threat reputation enrichment.
          </p>
        </div>

        <Button
          onClick={handleBatchEnrichAll}
          disabled={isLoading}
          className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shrink-0 shadow-md shadow-cyan-600/20"
        >
          <Sparkles className={cn("h-3.5 w-3.5", isLoading && "animate-spin")} />
          Enrich All Extracted IOCs
        </Button>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {(
            [
              { id: "all", label: "All Artifacts", count: allArtifacts.length },
              { id: "url", label: "URLs", count: allArtifacts.filter((a) => a.type === "url").length },
              { id: "domain", label: "Domains", count: allArtifacts.filter((a) => a.type === "domain").length },
              { id: "ip", label: "Observed IPs", count: allArtifacts.filter((a) => a.type === "ip").length },
              { id: "email", label: "Addresses", count: allArtifacts.filter((a) => a.type === "email").length },
              { id: "attachment", label: "Attachments", count: allArtifacts.filter((a) => a.type === "attachment").length },
            ] as const
          ).map((cat) => (
            <button
              key={cat.id}
              onClick={() => setFilterCategory(cat.id)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap flex items-center gap-1.5",
                filterCategory === cat.id
                  ? "bg-cyan-600 text-white shadow-sm"
                  : "bg-muted/40 text-muted-foreground hover:text-foreground hover:bg-muted/70"
              )}
            >
              {cat.label}
              <span
                className={cn(
                  "text-[10px] px-1.5 py-0.2 rounded-full",
                  filterCategory === cat.id ? "bg-white/20 text-white" : "bg-background/80 text-muted-foreground"
                )}
              >
                {cat.count}
              </span>
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search artifacts or sources..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs bg-muted/30 font-mono"
          />
        </div>
      </div>

      {filteredArtifacts.length === 0 ? (
        <EmptyState
          icon={Fingerprint}
          title="No Artifacts Found"
          description="No technical artifacts match the selected filters."
        />
      ) : (
        <motion.div 
          className="space-y-2"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.03 } } }}
          initial="hidden"
          animate="show"
        >
          {filteredArtifacts.map((item) => {
            const enriched = enrichedIndicators[item.value.toLowerCase()];
            const hasIntel = !!enriched;

            return (
              <motion.div key={item.id} variants={{ hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0 } }}>
              <Card className="border-border/40 bg-card/40 hover:bg-card/70 transition-colors surface-1 hover-lift">
                <CardContent className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="p-1.5 rounded bg-muted/60 shrink-0">{getIcon(item.type)}</div>
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-foreground break-all">{item.value}</span>
                        {hasIntel && (
                          <Badge
                            className={cn(
                              "text-[9px] font-mono uppercase font-bold",
                              enriched.overall_verdict === "malicious"
                                ? "bg-red-500/20 text-red-400 border-red-500/40"
                                : enriched.overall_verdict === "suspicious"
                                ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                                : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                            )}
                          >
                            Intel: {enriched.overall_verdict}
                            {enriched.max_reputation_score ? ` (${enriched.max_reputation_score}/100)` : ""}
                          </Badge>
                        )}
                        {item.type === "url" && urlResults[item.value] && (
                          <SeverityBadge
                            severity={urlResults[item.value].severity.toLowerCase()}
                            score={urlResults[item.value].threat_score}
                            size="sm"
                          />
                        )}
                      </div>
                      <span className="text-[10px] text-muted-foreground block truncate">
                        Observed in: {item.evidenceReference}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                    {item.type === "url" ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={async () => {
                          const existing = urlResults[item.value];
                          if (existing) {
                            setSelectedUrlResult(existing);
                          } else {
                            toast.loading("Inspecting URL structure and transport headers...");
                            const res = await analyzeUrl(item.value, item.evidenceReference, item.emailId);
                            toast.dismiss();
                            if (res) {
                              setSelectedUrlResult(res);
                              toast.success(`URL Scored: ${res.threat_score}/100 (${res.severity})`);
                            } else {
                              toast.error("Failed to analyze URL.");
                            }
                          }
                        }}
                        disabled={isUrlAnalyzing}
                        className="text-[11px] h-7 text-cyan-400 hover:text-cyan-300 border-cyan-500/30 gap-1 font-mono bg-cyan-500/10"
                      >
                        <Eye className="h-3 w-3" />
                        {urlResults[item.value] ? "View Intel" : "Inspect URL"}
                      </Button>
                    ) : !hasIntel && (item.type === "domain" || item.type === "ip") ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => enrichIndicator(item.value, item.type)}
                        disabled={isLoading}
                        className="text-[11px] h-7 text-muted-foreground hover:text-foreground gap-1 font-mono"
                      >
                        <Sparkles className="h-3 w-3 text-cyan-400" />
                        Enrich
                      </Button>
                    ) : null}

                    <Link href="/investigations">
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-[10px] h-6 text-muted-foreground hover:text-foreground gap-1 font-mono px-2"
                      >
                        <Network className="h-3 w-3 text-cyan-400" />
                        Graph
                      </Button>
                    </Link>

                    <span className="text-[10px] text-muted-foreground/80 font-mono truncate max-w-[180px]">
                      {item.emailSubject}
                    </span>
                    <Badge variant="outline" className="text-[9px] font-mono uppercase bg-background/50">
                      {item.type}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
              </motion.div>
            );
          })}
        </motion.div>
      )}

      {/* URL Forensic Detail Drawer */}
      <UrlDetailDrawer
        urlResult={selectedUrlResult}
        onClose={() => setSelectedUrlResult(null)}
      />
    </div>
  );
}
