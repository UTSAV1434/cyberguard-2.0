import os
import sys
import json
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv

# Reconfigure console output encoding for Windows compatibility
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger("CyberGuardAI")

from integrations.armorclaw import ArmorClawClient
from integrations.armoriq import ArmorIQClient
from integrations.notion import NotionClient
from services.audit_service import AuditService
from services.policy_service import PolicyService
from services.incident_service import IncidentService
from agents.threat_analyzer import ThreatAnalyzer
from agents.response_agent import ResponseAgent
from agents.rollback_agent import RollbackAgent

def get_clients_and_services():
    """Initializes and returns the shared services and clients."""
    mock_mode = os.getenv("MOCK_MODE", "True").lower() == "true"
    
    # Check credentials to auto-disable mock mode if they exist
    notion_token = os.getenv("NOTION_TOKEN")
    notion_db = os.getenv("NOTION_DATABASE_ID")
    armoriq_key = os.getenv("ARMORIQ_API_KEY")
    armorclaw_key = os.getenv("ARMORCLAW_API_KEY")
    
    if mock_mode:
        logger.info("🔧 CyberGuard AI running in MOCK mode. System operations simulated locally.")
    else:
        logger.info("🚀 CyberGuard AI running in LIVE mode. Connecting to external APIs.")

    claw_client = ArmorClawClient(api_key=armorclaw_key, mock_mode=mock_mode)
    iq_client = ArmorIQClient(api_key=armoriq_key, mock_mode=mock_mode)
    notion_client = NotionClient(token=notion_token, database_id=notion_db, mock_mode=mock_mode)
    
    audit_service = AuditService()
    policy_service = PolicyService(armoriq_client=iq_client)
    incident_service = IncidentService(
        audit_service=audit_service,
        policy_service=policy_service,
        armorclaw_client=claw_client,
        notion_client=notion_client
    )
    
    analyzer = ThreatAnalyzer()
    response_agent = ResponseAgent(incident_service=incident_service)
    rollback_agent = RollbackAgent(
        incident_service=incident_service,
        policy_service=policy_service,
        audit_service=audit_service,
        notion_client=notion_client
    )
    
    return analyzer, response_agent, rollback_agent, incident_service, notion_client

def cmd_run_simulation(args):
    """Command to execute log analysis threat simulation."""
    if not os.path.exists(args.file):
        logger.error(f"Log file not found: {args.file}")
        sys.exit(1)

    print("\n" + "="*80)
    print(f"🤖 CYBERGUARD AI - PROCESSING SECURITY LOGS ({datetime.utcnow().isoformat()})")
    print("="*80)
    
    try:
        with open(args.file, "r") as f:
            logs = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse log file: {str(e)}")
        sys.exit(1)

    analyzer, response_agent, _, _, notion_client = get_clients_and_services()
    
    print(f"Loaded {len(logs)} log entries. Analysing login attempts...")
    detected_threats = analyzer.analyze_logs(logs)
    print(f"Threat analysis complete. Found {len(detected_threats)} threat scenarios.\n")

    for threat in detected_threats:
        ip = threat["ip_address"]
        print(f"🛡️  [Analyzer Output] IP: {ip} | Threat: {threat['threat_type']} | Severity: {threat['severity']} | Risk: {threat['risk_score']}/100")
        print(f"   Action: {threat['recommended_action']} (Confidence: {threat['confidence']}%)")
        print(f"   Reason: {threat['explanation']}")
        print("-" * 80)
        
        # Hand off threat to ResponseAgent for mitigation
        incident = response_agent.handle_threat(threat)
        
        # Display response summary
        print(f"🔍 [Response Agent Output] Incident ID: {incident.id}")
        print(f"   Status: {incident.status}")
        print(f"   ArmorClaw verified: {incident.armorclaw_result.get('verified')} (Reputation: {incident.armorclaw_result.get('reputation')})")
        print(f"   ArmorIQ Policy: {incident.armoriq_decision.get('policy_name')} -> Approved: {incident.armoriq_decision.get('approved')}")
        print(f"   Action Executed: {incident.executed_action}")
        print("="*80 + "\n")

    if notion_client.mock_mode:
        print(f"💾 Mock Notion entries saved to local JSON file: {notion_client.mock_db_path}")

def cmd_undo(args):
    """Command to rollback/undo an IP block action."""
    print("\n" + "="*80)
    print(f"↩️ CYBERGUARD AI - TRIGGERING UNDO / ROLLBACK SEQUENCE")
    print("="*80)
    print(f"Target Incident ID: {args.incident_id}")
    print(f"Reversal Reason:    {args.reason}")
    print("-" * 80)

    _, _, rollback_agent, _, _ = get_clients_and_services()
    result = rollback_agent.rollback_incident(args.incident_id, args.reason)

    if result["success"]:
        print(f"\n✅ Rollback Succeeded: {result['message']}")
    else:
        print(f"\n❌ Rollback Failed: {result['message']}")
    print("="*80 + "\n")

def cmd_show_blocks(args):
    """Command to list blocked IP addresses."""
    _, _, _, incident_service, _ = get_clients_and_services()
    blocked = incident_service._get_blocked_ips()
    
    print("\n" + "="*80)
    print("🛡️  CURRENT FIREWALL BLOCKLIST STATE")
    print("="*80)
    if blocked:
        for idx, ip in enumerate(blocked, 1):
            print(f" {idx}. IP: {ip} [BLOCKED]")
    else:
        print(" No IP addresses are currently blocked.")
    print("="*80 + "\n")

def cmd_bootstrap(args):
    """Command to bootstrap a Notion database."""
    token = os.getenv("NOTION_TOKEN")
    page_id = args.page_id or os.getenv("NOTION_PAGE_ID")
    
    if not token or not page_id:
        print("❌ Error: NOTION_TOKEN and NOTION_PAGE_ID must be set in environment or arguments.")
        sys.exit(1)

    print("\n" + "="*80)
    print("⚡ NOTION DATABASE BOOTSTRAP")
    print("="*80)
    print(f"Connecting to Notion under parent page ID: {page_id}...")
    
    # Initialize client manually in live mode for bootstrap
    notion_client = NotionClient(token=token, database_id="dummy", mock_mode=False)
    new_db_id = notion_client.bootstrap_database(page_id)
    
    if new_db_id:
        print(f"\n✅ Database created successfully!")
        print(f"   Database ID: {new_db_id}")
        print("\n👉 Please update NOTION_DATABASE_ID in your .env file with this ID:")
        print(f"   NOTION_DATABASE_ID={new_db_id}")
        print("   Also, ensure MOCK_MODE is set to False to query live Notion API.")
    else:
        print("\n❌ Failed to bootstrap Notion database. Check your API permissions and parent page ID.")
    print("="*80 + "\n")

def main():
    parser = argparse.ArgumentParser(description="CyberGuard AI - Intelligent Incident Detection & Response CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # run-simulation sub-parser
    p_sim = subparsers.add_parser("run-simulation", help="Analyze authentication logs and run security simulation")
    p_sim.add_argument("--file", default="sample_logs/auth_failures.json", help="Path to sample auth failures JSON file")

    # undo sub-parser
    p_undo = subparsers.add_parser("undo", help="Rollback an IP block action")
    p_undo.add_argument("--incident-id", required=True, help="Incident ID to revert")
    p_undo.add_argument("--reason", default="False Positive", help="Reason for rollback execution")

    # show-blocks sub-parser
    subparsers.add_parser("show-blocks", help="List all currently blocked IPs in the firewall")

    # bootstrap-notion sub-parser
    p_boot = subparsers.add_parser("bootstrap-notion", help="Bootstrap a new incident database in Notion")
    p_boot.add_argument("--page-id", help="Parent Notion page ID under which database will be created")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "run-simulation":
        cmd_run_simulation(args)
    elif args.command == "undo":
        cmd_undo(args)
    elif args.command == "show-blocks":
        cmd_show_blocks(args)
    elif args.command == "bootstrap-notion":
        cmd_bootstrap(args)

if __name__ == "__main__":
    main()
