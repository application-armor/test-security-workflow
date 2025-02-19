import os
import json
import requests
from datetime import datetime

class VulnerabilitySync:
    def __init__(self):
        # GitHub configuration
        self.github_token = os.environ['GITHUB_TOKEN']
        self.github_repo = os.environ['GITHUB_REPOSITORY']
        self.github_api = "https://api.github.com"
        
        # Jira configuration
        self.jira_token = os.environ['JIRA_API_TOKEN']
        self.jira_email = os.environ['JIRA_EMAIL']
        self.jira_base_url = os.environ['JIRA_BASE_URL']
        self.jira_epic_key = os.environ['JIRA_EPIC_KEY']
        
        # Headers for API requests
        self.github_headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.jira_headers = {
            'Authorization': f'Basic {self._get_jira_auth()}',
            'Content-Type': 'application/json'
        }

    def _get_jira_auth(self):
        import base64
        creds = f"{self.jira_email}:{self.jira_token}"
        return base64.b64encode(creds.encode()).decode()

    def get_security_alerts(self):
        """Fetch security vulnerability alerts from GitHub"""
        url = f"{self.github_api}/repos/{self.github_repo}/code-scanning/alerts"
        response = requests.get(url, headers=self.github_headers)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch GitHub alerts: {response.text}")
        return response.json()

    def create_jira_issue(self, vulnerability):
        """Create a new Jira issue for a vulnerability"""
        url = f"{self.jira_base_url}/rest/api/2/issue"
        
        # Extract severity from rule description or default to Medium
        severity = "Medium"
        if "rule" in vulnerability:
            rule_desc = vulnerability["rule"].get("description", "").lower()
            if "critical" in rule_desc:
                severity = "Critical"
            elif "high" in rule_desc:
                severity = "High"
            elif "low" in rule_desc:
                severity = "Low"

        # Map severity to priority
        priority_map = {
            "Critical": "1",
            "High": "2",
            "Medium": "3",
            "Low": "4"
        }
        
        data = {
            "fields": {
                "project": {"key": self.jira_epic_key.split("-")[0]},
                "summary": f"Security Alert: {vulnerability.get('rule', {}).get('description', 'Unknown Vulnerability')}",
                "description": (
                    f"*Security Vulnerability Details*\n\n"
                    f"Tool: {vulnerability.get('tool', {}).get('name', 'Unknown')}\n"
                    f"Severity: {severity}\n"
                    f"Location: {vulnerability.get('most_recent_instance', {}).get('location', {}).get('path', 'Unknown')}\n"
                    f"Details: {vulnerability.get('rule', {}).get('description', 'No details available')}\n\n"
                    f"GitHub Alert: {vulnerability.get('html_url', 'No URL available')}"
                ),
                "issuetype": {"name": "Bug"},
                "priority": {"id": priority_map.get(severity, "3")},
                "customfield_10014": self.jira_epic_key  # Epic link field
            }
        }
        
        response = requests.post(url, headers=self.jira_headers, json=data)
        if response.status_code not in [201, 200]:
            raise Exception(f"Failed to create Jira issue: {response.text}")
        return response.json()

    def get_existing_issues(self):
        """Get existing Jira issues linked to the epic"""
        jql = f'cf[10014] = {self.jira_epic_key}'  # 10014 is epic link field
        url = f"{self.jira_base_url}/rest/api/2/search"
        response = requests.get(
            url,
            headers=self.jira_headers,
            params={'jql': jql, 'fields': 'summary,description'}
        )
        if response.status_code != 200:
            raise Exception(f"Failed to fetch Jira issues: {response.text}")
        return response.json().get('issues', [])

    def sync_vulnerabilities(self):
        """Main function to sync vulnerabilities from GitHub to Jira"""
        print("Starting vulnerability sync...")
        
        # Get GitHub security alerts
        alerts = self.get_security_alerts()
        print(f"Found {len(alerts)} security alerts")
        
        # Get existing Jira issues
        existing_issues = self.get_existing_issues()
        existing_summaries = {issue['fields']['summary'] for issue in existing_issues}
        
        # Process each alert
        created_count = 0
        for alert in alerts:
            summary = f"Security Alert: {alert.get('rule', {}).get('description', 'Unknown Vulnerability')}"
            if summary not in existing_summaries:
                try:
                    self.create_jira_issue(alert)
                    created_count += 1
                    print(f"Created Jira issue for: {summary}")
                except Exception as e:
                    print(f"Error creating issue for {summary}: {str(e)}")
        
        print(f"Sync completed. Created {created_count} new issues.")

if __name__ == "__main__":
    try:
        syncer = VulnerabilitySync()
        syncer.sync_vulnerabilities()
    except Exception as e:
        print(f"Error during sync: {str(e)}")
        exit(1)
