"use client";

import { useState, useMemo, useEffect } from "react";
import { useEmailStore } from "@/lib/email-store";
import { useIntelligenceStore } from "@/lib/intelligence-store";
import { useURLIntelligenceStore, URLAnalysisResult } from "@/lib/url-intelligence-store";
import { UrlDetailDrawer } from "@/components/security/UrlDetailDrawer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { SecurityMetricCard } from '@/components/security/SecurityMetricCard';
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
  Layers, 
  Copy, 
  ChevronLeft, 
  ChevronRight, 
  Table2, 
  LayoutGrid
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

  const [currentPage, setCurrentPage] = useState(1);
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [expandedValues, setExpandedValues] = useState<Set<string>>(new Set());
  const ITEMS_PER_PAGE = 50;

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

  const urlCount = allArtifacts.filter(a => a.type === 'url').length;
  const domainCount = allArtifacts.filter(a => a.type === 'domain').length;
  const ipCount = allArtifacts.filter(a => a.type === 'ip').length;
  const queryableArtifacts = allArtifacts.filter(a => a.type === 'domain' || a.type === 'ip' || a.type === 'url');
  const enrichedCount = queryableArtifacts.filter(a => !!enrichedIndicators[a.value.toLowerCase()]).length;
  const enrichmentPct = queryableArtifacts.length > 0 ? Math.round((enrichedCount / queryableArtifacts.length) * 100) : 0;

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredArtifacts.length / ITEMS_PER_PAGE));
  const paginatedArtifacts = filteredArtifacts.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  // Add useEffect to reset page when filter changes
  useEffect(() => { setCurrentPage(1); }, [filterCategory, searchQuery]);

  const truncateValue = (val: string, maxLen: number = 65): string => {
    if (val.length <= maxLen) return val;
    const start = val.substring(0, 35);
    const end = val.substring(val.length - 20);
    return `${start}…${end}`;
  };

  const handleCopyValue = (value: string) => {
    navigator.clipboard.writeText(value);
    toast.success('Copied full indicator to clipboard');
  };

  const toggleExpand = (id: string) => {
    setExpandedValues(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const getVerdictAccent = (value: string): string => {
    const enriched = enrichedIndicators[value.toLowerCase()];
    if (!enriched) return 'border-l-cyan-500/40';
    if (enriched.overall_verdict === 'malicious') return 'border-l-red-500/60';
    if (enriched.overall_verdict === 'suspicious') return 'border-l-amber-500/60';
    return 'border-l-emerald-500/60';
  };

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

  const FILTER_TABS = [
    { id: 'all' as FilterCategory, label: 'All Artifacts', icon: Layers, count: allArtifacts.length },
    { id: 'url' as FilterCategory, label: 'URLs', icon: LinkIcon, count: allArtifacts.filter(a => a.type === 'url').length },
    { id: 'domain' as FilterCategory, label: 'Domains', icon: Globe, count: allArtifacts.filter(a => a.type === 'domain').length },
    { id: 'ip' as FilterCategory, label: 'Observed IPs', icon: Radio, count: allArtifacts.filter(a => a.type === 'ip').length },
    { id: 'email' as FilterCategory, label: 'Addresses', icon: Mail, count: allArtifacts.filter(a => a.type === 'email').length },
    { id: 'attachment' as FilterCategory, label: 'Attachments', icon: Paperclip, count: allArtifacts.filter(a => a.type === 'attachment').length },
  ];

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

      <motion.div
        className="grid grid-cols-2 lg:grid-cols-4 gap-4"
        variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05 } } }}
        initial="hidden" animate="show"
      >
        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }}>
          <SecurityMetricCard title="Extracted Artifacts" value={allArtifacts.length} subtitle={`From ${emails.length} emails`} icon={Fingerprint} variant="cyan" badgeText="ARTIFACTS" />
        </motion.div>
        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }}>
          <SecurityMetricCard title="URLs & Domains" value={urlCount + domainCount} subtitle={`${urlCount} URLs · ${domainCount} domains`} icon={Globe} variant="emerald" badgeText="WEB" />
        </motion.div>
        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }}>
          <SecurityMetricCard title="Observed IPs" value={ipCount} subtitle="Routing infrastructure" icon={Radio} variant="violet" badgeText="NETWORK" />
        </motion.div>
        <motion.div variants={{ hidden: { opacity: 0, y: 15 }, show: { opacity: 1, y: 0 } }}>
          <SecurityMetricCard title="Threat Enrichment" value={`${enrichmentPct}%`} subtitle={`${enrichedCount} of ${queryableArtifacts.length} enriched`} icon={Sparkles} variant={enrichedCount > 0 ? 'amber' : 'neutral'} badgeText="COVERAGE" />
        </motion.div>
      </motion.div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {FILTER_TABS.map((cat) => (
            <button key={cat.id} onClick={() => setFilterCategory(cat.id)} className={cn(
              'px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap flex items-center gap-1.5',
              filterCategory === cat.id ? 'bg-cyan-600 text-white shadow-sm' : 'bg-muted/40 text-muted-foreground hover:text-foreground hover:bg-muted/70'
            )}>
              <cat.icon className="h-3 w-3" />
              {cat.label}
              <span className={cn('text-[10px] px-1.5 py-0.2 rounded-full', filterCategory === cat.id ? 'bg-white/20 text-white' : 'bg-background/80 text-muted-foreground')}>{cat.count}</span>
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

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          Showing {paginatedArtifacts.length} of {filteredArtifacts.length} artifacts
        </span>
        <div className="flex items-center gap-1 bg-card/60 p-0.5 rounded-lg border border-border/40">
          <button onClick={() => setViewMode('cards')} className={cn('p-1.5 rounded-md transition-colors', viewMode === 'cards' ? 'bg-cyan-600 text-white' : 'text-muted-foreground hover:text-foreground')} title="Card View">
            <LayoutGrid className="h-3.5 w-3.5" />
          </button>
          <button onClick={() => setViewMode('table')} className={cn('p-1.5 rounded-md transition-colors', viewMode === 'table' ? 'bg-cyan-600 text-white' : 'text-muted-foreground hover:text-foreground')} title="Table View">
            <Table2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {filteredArtifacts.length === 0 ? (
        allArtifacts.length === 0 ? (
          <EmptyState
            icon={Fingerprint}
            title="No Technical Artifacts Extracted"
            description="No emails have been parsed yet. Sync your mailbox or load sample demo data in Settings to explore forensic indicators."
            actionLabel="Open Settings →"
            onAction={() => window.location.href = '/settings'}
            className="py-8"
          />
        ) : (
          <EmptyState
            icon={Search}
            title="No Artifacts Match Selected Filter"
            description="No indicators match your active query or type selection."
            actionLabel="Reset Filters"
            onAction={() => { setFilterCategory('all'); setSearchQuery(''); }}
            className="py-8"
          />
        )
      ) : (
        viewMode === 'cards' ? (
          <motion.div className="space-y-2" variants={{ hidden: {}, show: { transition: { staggerChildren: 0.03 } } }} initial="hidden" animate="show">
            {paginatedArtifacts.map((item) => {
              const enriched = enrichedIndicators[item.value.toLowerCase()];
              const hasIntel = !!enriched;
              const isExpanded = expandedValues.has(item.id);
              return (
                <motion.div key={item.id} variants={{ hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0 } }}>
                  <Card className={cn('border-border/40 bg-card/40 hover:bg-card/70 transition-colors surface-1 hover-lift border-l-[3px]', getVerdictAccent(item.value))}>
                    <CardContent className="p-3 flex items-center gap-3 text-xs">
                      <div className="p-1.5 rounded-md bg-muted/60 shrink-0 w-8 h-8 flex items-center justify-center">{getIcon(item.type)}</div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <button onClick={() => toggleExpand(item.id)} className="font-mono font-bold text-foreground text-left truncate hover:text-cyan-400 transition-colors" title={item.value}>
                            {isExpanded ? item.value : truncateValue(item.value)}
                          </button>
                          <button onClick={() => handleCopyValue(item.value)} className="shrink-0 p-1 rounded hover:bg-muted/60 text-muted-foreground hover:text-foreground transition-colors" title="Copy full value">
                            <Copy className="h-3 w-3" />
                          </button>
                          {hasIntel && (
                            <Badge className={cn('text-[9px] font-mono uppercase font-bold shrink-0',
                              enriched.overall_verdict === 'malicious' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                              enriched.overall_verdict === 'suspicious' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
                              'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                            )}>
                              {enriched.overall_verdict}{enriched.max_reputation_score ? ` (${enriched.max_reputation_score})` : ''}
                            </Badge>
                          )}
                          {item.type === 'url' && urlResults[item.value] && (
                            <SeverityBadge severity={urlResults[item.value].severity.toLowerCase()} score={urlResults[item.value].threat_score} size="sm" />
                          )}
                        </div>
                        <span className="text-[10px] text-muted-foreground block truncate mt-0.5">Observed in: {item.evidenceReference}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {item.type === 'url' ? (
                          <Button size="sm" variant="outline" onClick={async () => {
                            const existing = urlResults[item.value];
                            if (existing) { setSelectedUrlResult(existing); }
                            else {
                              toast.loading('Inspecting URL...');
                              const res = await analyzeUrl(item.value, item.evidenceReference, item.emailId);
                              toast.dismiss();
                              if (res) { setSelectedUrlResult(res); toast.success(`URL Scored: ${res.threat_score}/100`); }
                              else { toast.error('Failed to analyze URL.'); }
                            }
                          }} disabled={isUrlAnalyzing} className="text-[10px] h-7 text-cyan-400 border-cyan-500/30 gap-1 font-mono bg-cyan-500/10">
                            <Eye className="h-3 w-3" />{urlResults[item.value] ? 'View' : 'Inspect'}
                          </Button>
                        ) : !hasIntel && (item.type === 'domain' || item.type === 'ip') ? (
                          <Button size="sm" variant="ghost" onClick={() => enrichIndicator(item.value, item.type)} disabled={isLoading} className="text-[10px] h-7 text-muted-foreground hover:text-foreground gap-1 font-mono">
                            <Sparkles className="h-3 w-3 text-cyan-400" />Enrich
                          </Button>
                        ) : null}
                        <Link href="/investigations">
                          <Button size="sm" variant="outline" className="text-[10px] h-6 text-muted-foreground gap-1 font-mono px-2">
                            <Network className="h-3 w-3" />Graph
                          </Button>
                        </Link>
                        <Badge variant="outline" className="text-[9px] font-mono uppercase bg-background/50 shrink-0">{item.type}</Badge>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </motion.div>
        ) : (
          // Table View
          <div className="surface-1 rounded-xl border border-border/40 overflow-hidden">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="text-left px-3 py-2 text-muted-foreground font-semibold w-10">Type</th>
                  <th className="text-left px-3 py-2 text-muted-foreground font-semibold">Indicator Value</th>
                  <th className="text-left px-3 py-2 text-muted-foreground font-semibold w-24">Verdict</th>
                  <th className="text-left px-3 py-2 text-muted-foreground font-semibold w-48">Source</th>
                  <th className="text-right px-3 py-2 text-muted-foreground font-semibold w-28">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedArtifacts.map((item) => {
                  const enriched = enrichedIndicators[item.value.toLowerCase()];
                  const hasIntel = !!enriched;
                  return (
                    <tr key={item.id} className={cn('border-b border-border/20 hover:bg-card/60 transition-colors border-l-[3px]', getVerdictAccent(item.value))}>
                      <td className="px-3 py-2">{getIcon(item.type)}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate max-w-[400px]" title={item.value}>{truncateValue(item.value)}</span>
                          <button onClick={() => handleCopyValue(item.value)} className="shrink-0 p-0.5 rounded hover:bg-muted/60 text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /></button>
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        {hasIntel ? (
                          <span className={cn('text-[9px] uppercase font-bold', enriched.overall_verdict === 'malicious' ? 'text-red-400' : enriched.overall_verdict === 'suspicious' ? 'text-amber-400' : 'text-emerald-400')}>
                            {enriched.overall_verdict}
                          </span>
                        ) : <span className="text-muted-foreground/60">—</span>}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground truncate max-w-[180px]">{item.evidenceReference}</td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex items-center gap-1 justify-end">
                          {item.type === 'url' ? (
                            <Button size="sm" variant="ghost" onClick={async () => {
                              const existing = urlResults[item.value];
                              if (existing) { setSelectedUrlResult(existing); }
                              else { const res = await analyzeUrl(item.value, item.evidenceReference, item.emailId); if (res) setSelectedUrlResult(res); }
                            }} disabled={isUrlAnalyzing} className="text-[10px] h-6 px-1.5"><Eye className="h-3 w-3" /></Button>
                          ) : !hasIntel && (item.type === 'domain' || item.type === 'ip') ? (
                            <Button size="sm" variant="ghost" onClick={() => enrichIndicator(item.value, item.type)} disabled={isLoading} className="text-[10px] h-6 px-1.5"><Sparkles className="h-3 w-3" /></Button>
                          ) : null}
                          <Link href="/investigations"><Button size="sm" variant="ghost" className="text-[10px] h-6 px-1.5"><Network className="h-3 w-3" /></Button></Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}

      {filteredArtifacts.length > ITEMS_PER_PAGE && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-muted-foreground font-mono">
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage <= 1} className="h-7 text-xs gap-1 font-mono">
              <ChevronLeft className="h-3 w-3" />Previous
            </Button>
            <Button size="sm" variant="outline" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage >= totalPages} className="h-7 text-xs gap-1 font-mono">
              Next<ChevronRight className="h-3 w-3" />
            </Button>
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
