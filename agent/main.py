#!/usr/bin/env python3
"""
Main entry point for the AI agent that audits Solidity contracts for security vulnerabilities.
"""
import argparse
import sys
from agent.server import start_server
from agent.local import process_local
from agent.config import load_config

def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description="AI Agent for Solidity security auditing")
    parser.add_argument("mode", choices=["server", "local"], help="Run mode: server or local")
    
    # Local mode arguments
    parser.add_argument("--repo", help="GitHub repository URL (required for local mode)")
    parser.add_argument("--commit", help="Specific commit hash to audit (optional for local mode)")
    parser.add_argument("--output", help="Output file path (for local mode)", default="security_audit_results.txt")
    parser.add_argument("--only-selected-files", action="store_true", help="Display and select specific .sol files to audit")
    
    # Server mode arguments
    parser.add_argument("--host", help="Host for the server (server mode)", default="0.0.0.0")
    parser.add_argument("--port", help="Port for the server (server mode)", type=int, default=8000)
    parser.add_argument(
        "--localtunnel",
        action="store_true",
        help="Expose server publicly through localtunnel (server mode)",
    )
    parser.add_argument(
        "--localtunnel-subdomain",
        help="Preferred localtunnel subdomain for a stable URL (server mode)",
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    
    if args.mode == "server":
        # Validate required fields for server mode
        if not config.webhook_auth_token:
            print("Error: WEBHOOK_AUTH_TOKEN is required for server mode")
            print("Please set the WEBHOOK_AUTH_TOKEN environment variable or add it to your .env file")
            sys.exit(1)
        
        if not config.agentarena_api_key:
            print("Error: AGENTARENA_API_KEY is required for server mode")
            print("Please set the AGENTARENA_API_KEY environment variable or add it to your .env file")
            sys.exit(1)

        if args.localtunnel:
            config.enable_localtunnel = True
        if args.localtunnel_subdomain:
            config.localtunnel_subdomain = args.localtunnel_subdomain
            
        start_server(host=args.host, port=args.port, config=config)
    elif args.mode == "local":
        if not args.repo:
            print("Error: --repo argument is required for local mode")
            parser.print_help()
            sys.exit(1)

        process_local(repo_url=args.repo, output_path=args.output, config=config, commit_hash=args.commit, only_selected=args.only_selected_files)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
