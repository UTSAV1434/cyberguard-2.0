import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class NotionClient:
    def __init__(self, token: Optional[str] = None, database_id: Optional[str] = None, mock_mode: bool = True):
        self.token = token or os.getenv("NOTION_TOKEN")
        self.database_id = database_id or os.getenv("NOTION_DATABASE_ID")
        self.mock_mode = mock_mode
        
        # If credentials are provided and mock mode isn't explicitly locked, turn off mock mode
        if self.token and self.database_id and os.getenv("MOCK_MODE", "True").lower() != "true":
            self.mock_mode = False
            
        if os.environ.get("VERCEL"):
            self.mock_db_path = "/tmp/notion_database_mock.json"
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.mock_db_path = os.path.join(base_dir, "notion_database_mock.json")
        if self.mock_mode:
            self._init_mock_db()

    def _init_mock_db(self):
        """Initializes the mock JSON database if it doesn't exist."""
        if not os.path.exists(self.mock_db_path):
            with open(self.mock_db_path, "w") as f:
                json.dump({}, f, indent=4)

    def _read_mock_db(self) -> Dict[str, Any]:
        if not os.path.exists(self.mock_db_path):
            self._init_mock_db()
        try:
            with open(self.mock_db_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_mock_db(self, db: Dict[str, Any]):
        try:
            with open(self.mock_db_path, "w") as f:
                json.dump(db, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write mock Notion DB: {str(e)}")

    def create_incident_record(self, incident: Dict[str, Any]) -> str:
        """
        Creates a new incident record in Notion (or mock DB).
        Returns the page/record ID.
        """
        incident_id = incident.get("id")
        
        if self.mock_mode:
            logger.info(f"[Notion MOCK] Creating incident record for ID: {incident_id}")
            db = self._read_mock_db()
            
            # Format timeline for mock record
            timeline_str = "\n".join([
                f"[{t.get('timestamp')}] {t.get('event')}: {t.get('description')}" 
                for t in incident.get("timeline", [])
            ])
            
            record = {
                "Incident ID": incident_id,
                "Timestamp": incident.get("timestamp"),
                "IP Address": incident.get("ip_address"),
                "Threat Type": incident.get("threat_type"),
                "Risk Score": incident.get("risk_score"),
                "Severity": incident.get("severity"),
                "Recommended Action": incident.get("recommended_action"),
                "ArmorClaw Result": json.dumps(incident.get("armorclaw_result", {})),
                "ArmorIQ Decision": json.dumps(incident.get("armoriq_decision", {})),
                "Executed Action": incident.get("executed_action"),
                "Status": incident.get("status"),
                "Timeline": timeline_str,
                "Compliance Report": incident.get("compliance_report", ""),
                "Last Updated": datetime.utcnow().isoformat() + "Z"
            }
            db[incident_id] = record
            self._write_mock_db(db)
            return f"mock-page-{incident_id}"
        else:
            logger.info(f"[Notion LIVE] Creating incident record for ID: {incident_id} in Database: {self.database_id}")
            try:
                import requests
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Notion-Version": "2022-06-28"
                }
                
                # Format properties based on standard Notion database property schemas
                properties = {
                    "Incident ID": {"title": [{"text": {"content": incident_id}}]},
                    "Timestamp": {"rich_text": [{"text": {"content": incident.get("timestamp", "")}}]},
                    "IP Address": {"select": {"name": incident.get("ip_address", "0.0.0.0")}},
                    "Threat Type": {"select": {"name": incident.get("threat_type", "Unknown")}},
                    "Risk Score": {"number": incident.get("risk_score", 0)},
                    "Severity": {"select": {"name": incident.get("severity", "Low")}},
                    "Recommended Action": {"rich_text": [{"text": {"content": incident.get("recommended_action", "")}}]},
                    "ArmorClaw Result": {"rich_text": [{"text": {"content": json.dumps(incident.get("armorclaw_result", {}))}}]},
                    "ArmorIQ Decision": {"rich_text": [{"text": {"content": json.dumps(incident.get("armoriq_decision", {}))}}]},
                    "Executed Action": {"rich_text": [{"text": {"content": incident.get("executed_action", "None")}}]},
                    "Status": {"select": {"name": incident.get("status", "Pending Approval")}}
                }

                # Construct children block layout (Timeline & Compliance report)
                children_blocks = self._generate_page_content_blocks(incident)
                
                payload = {
                    "parent": {"database_id": self.database_id},
                    "properties": properties,
                    "children": children_blocks
                }

                response = requests.post("https://api.notion.com/v1/pages", headers=headers, json=payload, timeout=10)
                if response.status_code == 200:
                    page_data = response.json()
                    page_id = page_data.get("id")
                    logger.info(f"[Notion LIVE] Created page successfully with ID: {page_id}")
                    return page_id
                else:
                    logger.error(f"[Notion LIVE] Failed to create page. Status: {response.status_code}, Body: {response.text}")
                    # fallback to mock
                    self.mock_mode = True
                    self._init_mock_db()
                    return self.create_incident_record(incident)
            except Exception as e:
                logger.error(f"[Notion LIVE] Connection error: {str(e)}. Fallback applied.")
                self.mock_mode = True
                self._init_mock_db()
                return self.create_incident_record(incident)

    def update_incident_record(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """
        Updates an existing incident record status and properties.
        """
        if self.mock_mode:
            logger.info(f"[Notion MOCK] Updating incident record: {incident_id} with {updates}")
            db = self._read_mock_db()
            if incident_id in db:
                key_mapping = {
                    "status": "Status",
                    "Status": "Status",
                    "executed_action": "Executed Action",
                    "Executed Action": "Executed Action",
                    "timeline": "Timeline",
                    "Timeline": "Timeline",
                    "compliance_report": "Compliance Report",
                    "Compliance Report": "Compliance Report",
                    "armoriq_decision": "ArmorIQ Decision",
                    "ArmorIQ Decision": "ArmorIQ Decision",
                    "armorclaw_result": "ArmorClaw Result",
                    "ArmorClaw Result": "ArmorClaw Result"
                }
                for k, v in updates.items():
                    db_key = key_mapping.get(k, k)
                    if db_key == "Timeline" and isinstance(v, list):
                        # Format timeline
                        timeline_str = "\n".join([
                            f"[{t.get('timestamp')}] {t.get('event')}: {t.get('description')}" 
                            for t in v
                        ])
                        db[incident_id]["Timeline"] = timeline_str
                    else:
                        db[incident_id][db_key] = v
                db[incident_id]["Last Updated"] = datetime.utcnow().isoformat() + "Z"
                self._write_mock_db(db)
                return True
            return False
        else:
            logger.info(f"[Notion LIVE] Updating incident record: {incident_id} with properties {updates}")
            # Find page ID from database query
            page_id = self.find_page_id_by_incident_id(incident_id)
            if not page_id:
                logger.warning(f"Could not find page for incident ID: {incident_id}")
                return False
            
            try:
                import requests
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Notion-Version": "2022-06-28"
                }

                # Construct properties update payload
                properties = {}
                if "status" in updates:
                    properties["Status"] = {"select": {"name": updates["status"]}}
                if "executed_action" in updates:
                    properties["Executed Action"] = {"rich_text": [{"text": {"content": updates["executed_action"]}}]}
                if "armoriq_decision" in updates:
                    properties["ArmorIQ Decision"] = {"rich_text": [{"text": {"content": json.dumps(updates["armoriq_decision"])}}]}
                if "compliance_report" in updates:
                    # In addition to database column, we will append a paragraph block below
                    properties["Compliance Report"] = {"rich_text": [{"text": {"content": updates["compliance_report"]}}]}

                payload = {"properties": properties}
                response = requests.patch(f"https://api.notion.com/v1/pages/{page_id}", headers=headers, json=payload, timeout=10)
                
                # If timeline is updated, append new timeline block items
                if "timeline" in updates:
                    self._append_timeline_blocks(page_id, updates["timeline"])

                return response.status_code == 200
            except Exception as e:
                logger.error(f"[Notion LIVE] Update error: {str(e)}")
                return False

    def find_page_id_by_incident_id(self, incident_id: str) -> Optional[str]:
        """Queries Notion database to find page ID associated with an Incident ID."""
        if self.mock_mode:
            return f"mock-page-{incident_id}"
            
        try:
            import requests
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Notion-Version": "2022-06-28"
            }
            payload = {
                "filter": {
                    "property": "Incident ID",
                    "title": {
                        "equals": incident_id
                    }
                }
            }
            response = requests.post(f"https://api.notion.com/v1/databases/{self.database_id}/query", headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                results = response.json().get("results", [])
                if results:
                    return results[0].get("id")
            return None
        except Exception as e:
            logger.error(f"Error querying Notion database: {str(e)}")
            return None

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """
        Retrieves all incident records from Notion (or mock DB).
        """
        if self.mock_mode:
            db = self._read_mock_db()
            incidents = []
            for inc_id, record in db.items():
                incidents.append(record)
            # Sort by Timestamp descending (newest first)
            incidents.sort(key=lambda x: x.get("Timestamp", "") or x.get("timestamp", ""), reverse=True)
            return incidents
        else:
            try:
                import requests
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "Notion-Version": "2022-06-28"
                }
                response = requests.post(f"https://api.notion.com/v1/databases/{self.database_id}/query", headers=headers, json={}, timeout=10)
                if response.status_code == 200:
                    results = response.json().get("results", [])
                    incidents = []
                    for page in results:
                        props = page.get("properties", {})
                        inc_id = ""
                        inc_title = props.get("Incident ID", {}).get("title", [])
                        if inc_title:
                            inc_id = inc_title[0].get("text", {}).get("content", "")
                        
                        ip_select = props.get("IP Address", {}).get("select") if props.get("IP Address") else None
                        ip = ip_select.get("name", "") if ip_select else "0.0.0.0"
                        
                        status_select = props.get("Status", {}).get("select") if props.get("Status") else None
                        status = status_select.get("name", "") if status_select else "Pending Approval"
                        
                        threat_select = props.get("Threat Type", {}).get("select") if props.get("Threat Type") else None
                        threat_type = threat_select.get("name", "") if threat_select else "Unknown"
                        
                        severity_select = props.get("Severity", {}).get("select") if props.get("Severity") else None
                        severity = severity_select.get("name", "") if severity_select else "Low"
                        
                        risk_score = props.get("Risk Score", {}).get("number", 0) if props.get("Risk Score") else 0
                        if risk_score is None:
                            risk_score = 0
                            
                        rec_action = ""
                        ra_prop = props.get("Recommended Action", {}).get("rich_text", []) if props.get("Recommended Action") else None
                        if ra_prop:
                            rec_action = ra_prop[0].get("text", {}).get("content", "")
                        
                        ts_prop = props.get("Timestamp", {}).get("rich_text", []) if props.get("Timestamp") else None
                        ts = ts_prop[0].get("text", {}).get("content", "") if ts_prop else ""
                        
                        executed = ""
                        ex_prop = props.get("Executed Action", {}).get("rich_text", []) if props.get("Executed Action") else None
                        if ex_prop:
                            executed = ex_prop[0].get("text", {}).get("content", "")

                        incidents.append({
                            "Incident ID": inc_id,
                            "id": inc_id,
                            "ip_address": ip,
                            "IP Address": ip,
                            "Status": status,
                            "status": status,
                            "Threat Type": threat_type,
                            "threat_type": threat_type,
                            "Severity": severity,
                            "severity": severity,
                            "Risk Score": risk_score,
                            "risk_score": risk_score,
                            "Recommended Action": rec_action,
                            "recommended_action": rec_action,
                            "Executed Action": executed,
                            "executed_action": executed,
                            "Timestamp": ts,
                            "timestamp": ts
                        })
                    return incidents
                return []
            except Exception as e:
                logger.error(f"Error querying live Notion DB incidents: {str(e)}")
                return []

    def _generate_page_content_blocks(self, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generates children page blocks including headings, timeline, and reports."""
        blocks = [
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {
                    "rich_text": [{"text": {"content": "AI Security Copilot Explanation"}}]
                }
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [{"text": {"content": incident.get("explanation", "No explanation provided.")}}]
                }
            },
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {
                    "rich_text": [{"text": {"content": "Security Timeline"}}]
                }
            }
        ]
        
        # Add timeline events
        for t in incident.get("timeline", []):
            blocks.append({
                "object": "block",
                "type": "bulleted_list_item",
                "bulleted_list_item": {
                    "rich_text": [
                        {"text": {"content": f"[{t.get('timestamp')}] "}, "annotations": {"bold": True}},
                        {"text": {"content": f"{t.get('event')}: {t.get('description')}"}}
                    ]
                }
            })

        # Add compliance report heading & body
        blocks.append({
            "object": "block",
            "type": "heading_2",
            "heading_2": {
                "rich_text": [{"text": {"content": "Compliance & Investigation Report"}}]
            }
        })
        
        report_text = incident.get("compliance_report", "Pending complete report generation.")
        # Notion paragraph blocks have length limitations. We split by double newlines to make paragraph blocks.
        for paragraph in report_text.split("\n\n"):
            if paragraph.strip():
                blocks.append({
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [{"text": {"content": paragraph.strip()}}]
                    }
                })

        return blocks

    def _append_timeline_blocks(self, page_id: str, timeline: List[Dict[str, Any]]):
        """Appends new timeline events to page children block list."""
        try:
            import requests
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Notion-Version": "2022-06-28"
            }
            
            blocks = []
            # For simplicity, we just add the latest timeline events
            # Standard implementation adds all timeline entries or filters the ones already added
            # For a hackathon project, appending a header and list of items is a clean solution
            blocks.append({
                "object": "block",
                "type": "heading_3",
                "heading_3": {
                    "rich_text": [{"text": {"content": "Timeline Update"}}]
                }
            })
            for t in timeline:
                blocks.append({
                    "object": "block",
                    "type": "bulleted_list_item",
                    "bulleted_list_item": {
                        "rich_text": [
                            {"text": {"content": f"[{t.get('timestamp')}] "}, "annotations": {"bold": True}},
                            {"text": {"content": f"{t.get('event')}: {t.get('description')}"}}
                        ]
                    }
                })
            
            requests.patch(f"https://api.notion.com/v1/blocks/{page_id}/children", headers=headers, json={"children": blocks}, timeout=10)
        except Exception as e:
            logger.error(f"Failed to append timeline blocks: {str(e)}")

    def bootstrap_database(self, parent_page_id: str) -> Optional[str]:
        """
        Creates a new CyberGuard Incidents database under a parent page.
        Returns the created database ID.
        """
        try:
            import requests
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Notion-Version": "2022-06-28"
            }
            
            payload = {
                "parent": {"type": "page_id", "page_id": parent_page_id},
                "title": [{"type": "text", "text": {"content": "CyberGuard AI Incidents"}}],
                "properties": {
                    "Incident ID": {"title": {}},
                    "Timestamp": {"rich_text": {}},
                    "IP Address": {"select": {}},
                    "Threat Type": {"select": {}},
                    "Risk Score": {"number": {}},
                    "Severity": {"select": {}},
                    "Recommended Action": {"rich_text": {}},
                    "ArmorClaw Result": {"rich_text": {}},
                    "ArmorIQ Decision": {"rich_text": {}},
                    "Executed Action": {"rich_text": {}},
                    "Status": {"select": {}},
                    "Compliance Report": {"rich_text": {}}
                }
            }
            response = requests.post("https://api.notion.com/v1/databases", headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                new_db_id = response.json().get("id")
                logger.info(f"Successfully bootstrapped Notion database. ID: {new_db_id}")
                return new_db_id
            else:
                logger.error(f"Failed to bootstrap database. Status: {response.status_code}, Body: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Exception during Notion bootstrap: {str(e)}")
            return None
