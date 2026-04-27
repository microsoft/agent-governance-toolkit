import os
import json
import sys
import re
from datetime import datetime, timedelta
from github import Github

def load_event_data():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        return None
    with open(event_path, "r") as f:
        return json.load(f)

def check_account_shape(user):
    """Check account age and follower ratio"""
    age_days = (datetime.utcnow() - user.created_at).days
    ratio = user.followers / max(1, user.following)
    suspicious_shape = age_days < 30 or (user.following > 50 and ratio < 0.1)
    return {
        "age_days": age_days,
        "followers": user.followers,
        "following": user.following,
        "public_repos": user.public_repos,
        "suspicious_shape": suspicious_shape
    }

def check_cross_repo_spray(gh, username, threshold, monitor_repos):
    """Check if the user has filed multiple similar issues in monitored repos recently."""
    if not monitor_repos:
        return {"spray_detected": False, "count": 0, "repos": []}
    
    # Query: author:username type:issue created:>7daysago
    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
    query = f"author:{username} type:issue created:>{seven_days_ago}"
    
    issues = gh.search_issues(query=query)
    
    repo_matches = set()
    total_count = 0
    for issue in issues:
        repo_name = issue.repository.full_name
        if repo_name in monitor_repos:
            repo_matches.add(repo_name)
            total_count += 1
            
    spray_detected = total_count >= threshold
    return {
        "spray_detected": spray_detected,
        "count": total_count,
        "repos": list(repo_matches)
    }

def check_credential_claims(body):
    """Check if the body references PRs in other repositories."""
    if not body:
        return {"claims_found": False, "urls": []}
    
    # Simple regex to find GitHub pull request URLs
    pr_url_pattern = re.compile(r'https://github\.com/[^/]+/[^/]+/pull/\d+')
    urls = pr_url_pattern.findall(body)
    
    return {
        "claims_found": len(urls) > 0,
        "urls": urls
    }

def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN is required.")
        sys.exit(1)
        
    gh = Github(token)
    
    # Parse inputs
    try:
        spray_threshold = int(os.environ.get("SPRAY_THRESHOLD", "3"))
    except ValueError:
        spray_threshold = 3
        
    check_spray = os.environ.get("CHECK_SPRAY", "true").lower() == "true"
    check_credentials = os.environ.get("CHECK_CREDENTIALS", "true").lower() == "true"
    
    monitor_repos_raw = os.environ.get("MONITOR_REPOS", "")
    monitor_repos = [r.strip() for r in monitor_repos_raw.split('\n') if r.strip()]
    
    watchlist_raw = os.environ.get("WATCHLIST", "[]")
    try:
        watchlist = json.loads(watchlist_raw)
    except Exception:
        watchlist = []
        
    event_data = load_event_data()
    if not event_data:
        # Fallback for local testing or manual trigger
        username = os.environ.get("TEST_USERNAME", "ghost")
        body = os.environ.get("TEST_BODY", "")
    else:
        if "pull_request" in event_data:
            item = event_data["pull_request"]
        elif "issue" in event_data:
            item = event_data["issue"]
        else:
            print("Unsupported event type")
            sys.exit(0)
            
        username = item["user"]["login"]
        body = item.get("body", "")

    print(f"Analyzing user: {username}")
    user = gh.get_user(username)
    
    # 1. Account Shape
    shape = check_account_shape(user)
    
    # 2. Watchlist
    in_watchlist = username in watchlist
    
    # 3. Spray Check
    spray = check_cross_repo_spray(gh, username, spray_threshold, monitor_repos) if check_spray else {"spray_detected": False}
    
    # 4. Credential Claims
    claims = check_credential_claims(body) if check_credentials else {"claims_found": False}
    
    # Calculate Risk
    risk_score = 0
    if shape.get("suspicious_shape"): risk_score += 1
    if in_watchlist: risk_score += 3
    if spray.get("spray_detected"): risk_score += 2
    if claims.get("claims_found"): risk_score += 1
    
    risk_level = "LOW"
    if risk_score >= 3:
        risk_level = "HIGH"
    elif risk_score >= 1:
        risk_level = "MEDIUM"
        
    findings = {
        "user": username,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "account_shape": shape,
        "in_watchlist": in_watchlist,
        "spray_analysis": spray,
        "credential_claims": claims
    }
    
    print(f"Findings: {json.dumps(findings, indent=2)}")
    
    # Write to GitHub Actions outputs
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"risk-level={risk_level}\n")
            f.write(f"spray-detected={str(spray.get('spray_detected', False)).lower()}\n")
            
            # EOF syntax for multiline JSON
            f.write("findings<<EOF\n")
            f.write(json.dumps(findings))
            f.write("\nEOF\n")
            
    # Post comment if risk is MEDIUM or HIGH and we're running in GitHub Actions
    if risk_level in ["MEDIUM", "HIGH"] and event_data:
        repo_name = os.environ.get("GITHUB_REPOSITORY")
        repo = gh.get_repo(repo_name)
        
        issue_number = event_data.get("pull_request", {}).get("number") or event_data.get("issue", {}).get("number")
        
        if issue_number:
            issue = repo.get_issue(number=issue_number)
            
            comment_body = f"⚠️ **PR Triage Action** ⚠️\n\n"
            comment_body += f"Detected **{risk_level}** risk profile for contributor `@'{username}'`.\n\n"
            
            if spray.get("spray_detected"):
                comment_body += f"- **Spray Detected**: Author has filed similar issues across {spray.get('count')} monitored repositories.\n"
            if claims.get("claims_found"):
                comment_body += f"- **Credential Claims**: Body cites PRs from other repositories to build credibility.\n"
            if shape.get("suspicious_shape"):
                comment_body += f"- **Suspicious Account Shape**: Account is very new or has a low follower/following ratio.\n"
                
            try:
                issue.create_comment(comment_body)
                issue.add_to_labels("needs-verification")
            except Exception as e:
                print(f"Failed to post comment or label: {e}")

if __name__ == "__main__":
    main()
