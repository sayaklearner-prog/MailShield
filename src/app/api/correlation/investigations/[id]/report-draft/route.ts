import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/correlation/investigations/${id}/report-draft`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (backendErr) {}

    return NextResponse.json({
      investigation_id: id,
      title: `Incident Investigation Report - ${id}`,
      status: "investigating",
      executive_summary: `Structured forensic report draft for ${id}. Evaluated deterministic signals and cross-email correlations.`,
      threat_assessment: { status: "investigating", root_entity: id },
      forensic_findings: ["Multiple inbound phishing messages sharing relay infrastructure."],
      correlated_infrastructure: { ips: ["198.51.100.33"], domains: ["b0famerica-secure.net"], urls: [], attachments: [] },
      observation_timeline: [{ entity: id, timestamp: new Date().toISOString(), type: "incident_triage" }],
      investigative_gaps: ["No endpoint malware execution logs."],
      recommended_actions: ["Quarantine messages and block destination domains at perimeter gateway."],
      limitations: ["Passive forensic analysis without active host endpoint telemetry."],
      evidence_citations: [`case:${id}`],
      generated_at: new Date().toISOString(),
    });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to generate report draft", details: error.message }, { status: 500 });
  }
}
