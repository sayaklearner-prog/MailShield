import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.correlation import (
    NodeType,
    RelationshipType,
    CorrelationStrength,
    RelationshipSourceType,
    CreateInvestigationRequest,
)
from backend.app.services.correlation.normalizer import CorrelationNormalizer
from backend.app.services.correlation.graph_builder import GraphBuilder
from backend.app.services.correlation.engine import CorrelationEngine, correlation_engine


class TestCorrelationAndGraphEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.engine = CorrelationEngine(seed_demo=True)
        correlation_engine.load_seed_demo_data()

    def test_normalization_and_deduplication(self):
        """Test canonical node ID generation across upper/lowercase and URL variants."""
        self.assertEqual(
            CorrelationNormalizer.normalize_node_id(NodeType.DOMAIN, "WWW.Example.COM"),
            "domain:example.com",
        )
        self.assertEqual(
            CorrelationNormalizer.normalize_node_id(NodeType.EMAIL_ADDRESS, "Support <Admin@Example.com>"),
            "email_address:admin@example.com",
        )
        self.assertEqual(
            CorrelationNormalizer.normalize_node_id(NodeType.ASN, "15169"),
            "asn:AS15169",
        )

    def test_shared_ip_and_domain_correlation(self):
        """Test that two emails referencing the same IP and domain correlate in the graph."""
        builder = GraphBuilder()

        email_1 = {
            "id": "email-A",
            "subject": "Phishing 1",
            "fromEmail": "fake@attacker.com",
            "receivedAt": "2026-08-30T10:00:00Z",
            "forensicData": {
                "receivedChain": [{"sequence": 1, "fromIp": "198.51.100.50"}],
                "urls": [{"url": "http://evil-site.org/login", "domain": "evil-site.org"}],
                "attachments": [{"filename": "invoice.pdf.exe", "sha256Hash": "deadbeef1234"}],
            },
        }

        email_2 = {
            "id": "email-B",
            "subject": "Phishing 2",
            "fromEmail": "fake2@attacker.com",
            "receivedAt": "2026-08-30T11:00:00Z",
            "forensicData": {
                "receivedChain": [{"sequence": 1, "fromIp": "198.51.100.50"}],
                "urls": [{"url": "http://evil-site.org/login", "domain": "evil-site.org"}],
                "attachments": [{"filename": "invoice_update.exe", "sha256Hash": "deadbeef1234"}],
            },
        }

        builder.process_email(email_1)
        builder.process_email(email_2)
        graph = builder.build_graph()

        # Check deduplicated nodes
        ip_node = next((n for n in graph.nodes if n.id == "ip:198.51.100.50"), None)
        self.assertIsNotNone(ip_node)
        self.assertEqual(ip_node.occurrence_count, 2)

        dom_node = next((n for n in graph.nodes if n.id == "domain:evil-site.org"), None)
        self.assertIsNotNone(dom_node)
        self.assertEqual(dom_node.occurrence_count, 2)

        att_node = next((n for n in graph.nodes if n.id == "attachment:deadbeef1234"), None)
        self.assertIsNotNone(att_node)
        self.assertEqual(att_node.occurrence_count, 2)

    def test_observed_vs_derived_relationships(self):
        """Test distinction between directly observed MIME/network facts and derived entities."""
        builder = GraphBuilder()
        builder.process_email({
            "id": "msg-single",
            "subject": "Test",
            "fromEmail": "attacker@bad.org",
            "forensicData": {
                "urls": [{"url": "http://bad.org/phish", "domain": "bad.org"}],
            },
        })
        graph = builder.build_graph()

        # Email -> URL is OBSERVED
        contains_edge = next((e for e in graph.edges if e.relationship == RelationshipType.CONTAINS), None)
        self.assertIsNotNone(contains_edge)
        self.assertEqual(contains_edge.source_type, RelationshipSourceType.OBSERVED)
        self.assertTrue(len(contains_edge.evidence_references) > 0)

        # URL -> Domain is DERIVED
        resolves_edge = next((e for e in graph.edges if e.relationship == RelationshipType.RESOLVES_TO), None)
        self.assertIsNotNone(resolves_edge)
        self.assertEqual(resolves_edge.source_type, RelationshipSourceType.DERIVED)

    def test_bounded_graph_traversal(self):
        """Test that BFS expansion respects depth boundaries and cycle safety."""
        # Query depth 1
        sub_d1 = self.engine.get_subgraph(root_id="email:msg-101", depth=1)
        self.assertGreater(sub_d1.total_nodes, 0)

        # Query depth 2 reaches connected second email (msg-102) via shared IP/domain
        sub_d2 = self.engine.get_subgraph(root_id="email:msg-101", depth=2)
        self.assertGreaterEqual(sub_d2.total_nodes, sub_d1.total_nodes)

        # Verify cycle safety (should not loop infinitely)
        email_ids = [n.normalized_value for n in sub_d2.nodes if n.type == NodeType.EMAIL]
        self.assertIn("msg-101", email_ids)

    def test_correlation_summary(self):
        """Test correlation summary calculation for shared indicators."""
        summary = self.engine.get_correlation_summary("ip:198.51.100.33")
        self.assertEqual(summary.entity_type, NodeType.IP)
        self.assertGreaterEqual(summary.occurrence_count, 2)
        self.assertIn("msg-101", summary.related_email_ids)
        self.assertIn("msg-102", summary.related_email_ids)

    def test_investigation_case_lifecycle(self):
        """Test investigation creation and listing."""
        req = CreateInvestigationRequest(
            title="Suspicious Campaign Test",
            root_entity_id="email:msg-101",
            root_entity_type="email",
            notes="Testing manual case file opening.",
        )
        case = self.engine.create_investigation(req)
        self.assertTrue(case.id.startswith("case-"))
        self.assertEqual(case.title, "Suspicious Campaign Test")
        self.assertIn("msg-101", case.related_email_ids)

    def test_api_correlation_endpoints(self):
        """Test FastAPI correlation endpoints."""
        # 1. Full Graph
        resp = self.client.get("/api/v1/correlation/graph")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

        # 2. Subgraph with root_id
        resp_sub = self.client.get("/api/v1/correlation/graph?root_id=email:msg-101&depth=2")
        self.assertEqual(resp_sub.status_code, 200)
        sub_data = resp_sub.json()
        self.assertGreater(sub_data["total_nodes"], 0)

        # 3. Correlation summary
        resp_sum = self.client.get("/api/v1/correlation/summary/ip:198.51.100.33")
        self.assertEqual(resp_sum.status_code, 200)
        sum_data = resp_sum.json()
        self.assertEqual(sum_data["entity_id"], "ip:198.51.100.33")

        # 4. List investigations
        resp_inv = self.client.get("/api/v1/correlation/investigations")
        self.assertEqual(resp_inv.status_code, 200)
        self.assertIsInstance(resp_inv.json(), list)


if __name__ == "__main__":
    unittest.main()
