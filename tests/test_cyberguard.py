import os
os.environ["MOCK_MODE"] = "True"
import unittest
import json
import shutil
from datetime import datetime
from agents.threat_analyzer import ThreatAnalyzer
from integrations.armorclaw import ArmorClawClient
from integrations.armoriq import ArmorIQClient
from integrations.notion import NotionClient
from services.audit_service import AuditService
from services.policy_service import PolicyService
from services.incident_service import IncidentService
from agents.response_agent import ResponseAgent
from agents.rollback_agent import RollbackAgent

class TestCyberGuard(unittest.TestCase):
    def setUp(self):
        # Setup temporary directories and path overrides for isolated testing
        self.test_dir = os.path.join("c:/Users/utsav/OneDrive/Desktop/uodated hackathon", "test_scratch")
        os.makedirs(self.test_dir, exist_ok=True)
        
        self.mock_db_path = os.path.join(self.test_dir, "notion_database_test.json")
        self.audit_log_path = os.path.join(self.test_dir, "audit_log_test.json")
        self.firewall_state_path = os.path.join(self.test_dir, "firewall_state_test.json")
        
        # Instantiate clients with mock_mode=True
        self.claw_client = ArmorClawClient(mock_mode=True)
        self.iq_client = ArmorIQClient(mock_mode=True)
        
        self.notion_client = NotionClient(mock_mode=True)
        self.notion_client.mock_db_path = self.mock_db_path
        self.notion_client._init_mock_db()
        
        self.audit_service = AuditService()
        self.audit_service.audit_log_path = self.audit_log_path
        self.audit_service._init_log()
        
        self.policy_service = PolicyService(armoriq_client=self.iq_client)
        
        self.incident_service = IncidentService(
            audit_service=self.audit_service,
            policy_service=self.policy_service,
            armorclaw_client=self.claw_client,
            notion_client=self.notion_client
        )
        self.incident_service.firewall_state_path = self.firewall_state_path
        self.incident_service._init_firewall_state()
        
        self.response_agent = ResponseAgent(incident_service=self.incident_service)
        self.rollback_agent = RollbackAgent(
            incident_service=self.incident_service,
            policy_service=self.policy_service,
            audit_service=self.audit_service,
            notion_client=self.notion_client
        )
        self.analyzer = ThreatAnalyzer()

    def tearDown(self):
        # Cleanup test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_threat_analyzer_critical(self):
        # 9 failures should result in Critical severity, Block IP recommendation
        logs = [
            {"timestamp": "2026-06-19T09:00:00Z", "ip_address": "1.2.3.4", "status": "failed"}
            for _ in range(9)
        ]
        threats = self.analyzer.analyze_logs(logs)
        self.assertEqual(len(threats), 1)
        threat = threats[0]
        self.assertEqual(threat["ip_address"], "1.2.3.4")
        self.assertEqual(threat["severity"], "Critical")
        self.assertEqual(threat["recommended_action"], "Block IP")
        self.assertEqual(threat["confidence"], 100)

    def test_threat_analyzer_false_positive(self):
        # 5 failures followed by a success -> High severity but low confidence (55%)
        logs = [
            {"timestamp": "2026-06-19T09:00:00Z", "ip_address": "5.6.7.8", "status": "failed"}
            for _ in range(5)
        ]
        logs.append({"timestamp": "2026-06-19T09:01:00Z", "ip_address": "5.6.7.8", "status": "success"})
        
        threats = self.analyzer.analyze_logs(logs)
        self.assertEqual(len(threats), 1)
        threat = threats[0]
        self.assertEqual(threat["severity"], "High")
        self.assertEqual(threat["confidence"], 55)
        self.assertEqual(threat["recommended_action"], "Require Human Approval")

    def test_policy_gating_false_positive(self):
        # Test that low confidence threat triggers escalation (is_approved=False)
        threat_data = {
            "ip_address": "5.6.7.8",
            "threat_type": "Brute Force Attack",
            "risk_score": 70,
            "severity": "High",
            "confidence": 55,
            "explanation": "Test escalation case."
        }
        is_approved, action, decision = self.policy_service.evaluate_containment_policy(threat_data)
        self.assertFalse(is_approved)
        self.assertEqual(action, "Require Human Approval")
        self.assertIn("Potential False Positive", decision["reason"])

    def test_policy_gating_critical_approved(self):
        # Test that high confidence, critical threat triggers auto block approval
        threat_data = {
            "ip_address": "1.2.3.4",
            "threat_type": "Brute Force Attack",
            "risk_score": 90,
            "severity": "Critical",
            "confidence": 100,
            "explanation": "Test critical case."
        }
        is_approved, action, decision = self.policy_service.evaluate_containment_policy(threat_data)
        self.assertTrue(is_approved)
        self.assertEqual(action, "Block IP")

    def test_incident_containment_execution(self):
        # Test full containment flow for critical threat
        threat_data = {
            "ip_address": "198.51.100.99", # ends in .99 so ArmorClaw reputation is High
            "threat_type": "Brute Force Attack",
            "risk_score": 90,
            "severity": "Critical",
            "confidence": 100,
            "explanation": "Test block case."
        }
        incident = self.response_agent.handle_threat(threat_data)
        
        # Verify state changes
        self.assertEqual(incident.status, "Action Executed")
        self.assertEqual(incident.executed_action, "Block IP")
        self.assertTrue(self.incident_service.is_ip_blocked("198.51.100.99"))
        
        # Verify local audit logs recorded the action
        audit_trail = self.audit_service.get_incident_audit_trail(incident.id)
        event_types = [e.event_type for e in audit_trail]
        self.assertIn("ACTION_EXECUTED", event_types)
        
        # Verify notion db contains record
        db = self.notion_client._read_mock_db()
        self.assertIn(incident.id, db)
        self.assertEqual(db[incident.id]["Status"], "Action Executed")

    def test_rollback_containment_action(self):
        # Test full rollback flow for blocked incident
        threat_data = {
            "ip_address": "198.51.100.99",
            "threat_type": "Brute Force Attack",
            "risk_score": 95,
            "severity": "Critical",
            "confidence": 100,
            "explanation": "Test rollback setup."
        }
        # 1. Trigger block
        incident = self.response_agent.handle_threat(threat_data)
        self.assertTrue(self.incident_service.is_ip_blocked("198.51.100.99"))
        
        # 2. Trigger rollback
        rollback_result = self.rollback_agent.rollback_incident(incident.id, "False Positive")
        self.assertTrue(rollback_result["success"])
        
        # 3. Verify state changes
        self.assertFalse(self.incident_service.is_ip_blocked("198.51.100.99"))
        
        # Verify Notion mock DB is updated
        db = self.notion_client._read_mock_db()
        self.assertEqual(db[incident.id]["Status"], "Rolled Back")
        self.assertEqual(db[incident.id]["Executed Action"], "Unblock IP")
        self.assertIn("Rollback Executed", db[incident.id]["Timeline"])
        
        # Verify audit logs recorded rollback
        audit_trail = self.audit_service.get_incident_audit_trail(incident.id)
        event_types = [e.event_type for e in audit_trail]
        self.assertIn("ROLLBACK_EXECUTED", event_types)

if __name__ == "__main__":
    unittest.main()
