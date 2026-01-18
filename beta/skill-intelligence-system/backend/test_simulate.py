import urllib.request
import json
import urllib.parse

BASE_URL = "http://localhost:8000"

def get_json(url):
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read().decode())

def post_json(url, data):
    req = urllib.request.Request(
        url, 
        data=json.dumps(data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())

def test_feature():
    print("Fetching roles...")
    try:
        roles = get_json(f"{BASE_URL}/roles/")
        if not roles:
            print("No roles found.")
            return
        
        target_role = roles[0]
        role_id = target_role['id']
        required_skill = target_role['required_skills'][0]
        skill_id = required_skill['skill_id']
        skill_name = required_skill['skill']['name']
        
        print(f"Testing Simulation for Role: {target_role['title']} (ID: {role_id})")
        print(f"Modifying Skill: {skill_name} (ID: {skill_id})")

        payload = {
            "user_id": 3,
            "role_id": role_id,
            "skill_id": skill_id,
            "target_level": 5
        }
        
        print(f"Sending Payload: {payload}")
        
        res_data = post_json(f"{BASE_URL}/roles/simulate", payload)
        
        print("\n--- SUCCESS ---")
        print(f"Current: {res_data['current_readiness']}")
        print(f"New:     {res_data['new_readiness']}")
        print(f"Delta:   +{res_data['improvement']}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_feature()
