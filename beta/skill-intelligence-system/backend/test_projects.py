import urllib.request
import json

BASE_URL = "http://localhost:8000"

def get_json(url):
    try:
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def test_projects():
    print("Fetching project recommendations for user 3...")
    projects = get_json(f"{BASE_URL}/projects/recommend/3")
    
    if projects:
        print(f"\n--- Found {len(projects)} Projects ---")
        for p in projects:
            print(f"[{p['relevance_score']*100:.0f}% Match] {p['title']} ({p['domain']})")
            print(f"   Skills: {', '.join([s['skill_name'] for s in p['required_skills']])}")
            print(f"   Repo: {p['github_repo_url']}")
            print("-" * 30)
    else:
        print("No projects returned or error occurred.")

if __name__ == "__main__":
    test_projects()
