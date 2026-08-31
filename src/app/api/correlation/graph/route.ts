import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const rootId = searchParams.get("root_id");
    const depth = searchParams.get("depth") || "2";
    const limit = searchParams.get("limit") || "100";

    const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
    const query = rootId
      ? `?root_id=${encodeURIComponent(rootId)}&depth=${depth}&limit=${limit}`
      : `?depth=${depth}&limit=${limit}`;

    try {
      const response = await fetch(`${fastApiUrl}/api/v1/correlation/graph${query}`);
      if (response.ok) {
        const data = await response.json();
        return NextResponse.json(data);
      }
    } catch (e) {
      // Backend not running / fallback
    }

    return NextResponse.json({
      nodes: [],
      edges: [],
      root_node_id: rootId,
      depth: parseInt(depth, 10),
      total_nodes: 0,
      total_edges: 0,
    });
  } catch (error: any) {
    return NextResponse.json({ error: "Failed to fetch graph", details: error.message }, { status: 500 });
  }
}
