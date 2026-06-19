import os
os.environ["MOCK_MODE"] = "True"
import unittest
import json
import shutil
from fastapi.testclient import TestClient
from server import app, notion_client, incident_service, audit_service

class TestCyberGuardAPI(unittest.TestCase):
    def setUp(self):
        # Override paths for test isolation
        self.test_dir = os.path.join("c:/Users/utsav/OneDrive/Desktop/uodated hackathon", "test_api_scratch")
        os.makedirs(self.test_dir, exist_ok=True)
        
        self.mock_db_path = os.path.join(self.test_dir, "notion_database_api_test.json")
        self.audit_log_path = os.path.join(self.test_dir, "audit_log_api_test.json")
        self.firewall_state_path = os.path.join(self.test_dir, "firewall_state_api_test.json")
        
        # Patch the active service and client instances in server.py
        notion_client.mock_db_path = self.mock_db_path
        notion_client._init_mock_db()
        
        audit_service.audit_log_path = self.audit_log_path
        audit_service._init_log()
        
        incident_service.firewall_state_path = self.firewall_state_path
        incident_service._init_firewall_state()
        
        self.client = TestClient(app)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_get_status(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "online")
        self.assertTrue(data["mock_mode"])

    def test_run_simulation_and_list_incidents(self):
        # 1. Trigger Simulation run via API
        response = self.client.post("/api/simulation/run")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertGreater(len(data["results"]), 0)
        
        # Find critical incident
        blocked_results = [r for r in data["results"] if r["executed_action"] == "Block IP"]
        self.assertGreater(len(blocked_results), 0)
        incident_id = blocked_results[0]["id"]
        ip_address = blocked_results[0]["ip_address"]

        # 2. Get Incidents list via API
        res_list = self.client.get("/api/incidents")
        self.assertEqual(res_list.status_code, 200)
        incidents_data = res_list.json()
        self.assertGreater(len(incidents_data), 0)
        
        # Verify specific incident is in list
        ids = [i.get("Incident ID") for i in incidents_data]
        self.assertIn(incident_id, ids)

        # 3. Get Details for specific Incident via API
        res_detail = self.client.get(f"/api/incidents/{incident_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail_data = res_detail.json()
        self.assertEqual(detail_data["Incident ID"], incident_id)
        self.assertEqual(detail_data["Status"], "Action Executed")
        
        # 4. Check blocked IPs list in firewall via API
        res_blocks = self.client.get("/api/firewall/blocks")
        self.assertEqual(res_blocks.status_code, 200)
        blocks_data = res_blocks.json()
        self.assertIn(ip_address, blocks_data["blocked_ips"])

        # 5. Rollback (undo) the block action via API
        res_undo = self.client.post(
            f"/api/incidents/{incident_id}/undo",
            json={"reason": "Testing Rollback API"}
        )
        self.assertEqual(res_undo.status_code, 200)
        undo_data = res_undo.json()
        self.assertTrue(undo_data["success"])

        # 6. Verify IP is removed from blocked list
        res_blocks_after = self.client.get("/api/firewall/blocks")
        self.assertEqual(res_blocks_after.status_code, 200)
        blocks_data_after = res_blocks_after.json()
        self.assertNotIn(ip_address, blocks_data_after["blocked_ips"])

        # 7. Verify status updated to Rolled Back
        res_detail_after = self.client.get(f"/api/incidents/{incident_id}")
        self.assertEqual(res_detail_after.status_code, 200)
        detail_data_after = res_detail_after.json()
        self.assertEqual(detail_data_after["Status"], "Rolled Back")

if __name__ == "__main__":
    unittest.main()
