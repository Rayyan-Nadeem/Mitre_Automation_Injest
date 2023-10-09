
import json

def load_data(filename):
    with open(filename, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def query_data(data, queries):
    results = []

    # Find matching techniques based on queries
    for item in data:
        match = True
        for key, value in queries.items():
            if value:  # If a query value is specified
                if isinstance(item.get(key), list):  # For fields with list values (e.g., platforms)
                    if not any(value in v for v in item.get(key, [])):  # Check for partial matches within the list
                        match = False
                        break
                elif item.get(key) != value:  # For fields with string values
                    match = False
                    break

        if match:
            results.append(item)
            # If a sub-technique is matched, fetch its parent and siblings
            if item['is sub-technique']:
                parent_id = item['sub-technique of']
                parent = next((tech for tech in data if tech['ID'] == parent_id), None)
                if parent:
                    results.append(parent)
                    siblings = [tech for tech in data if tech['sub-technique of'] == parent_id and tech['ID'] != item['ID']]
                    results.extend(siblings)

    return results

if __name__ == "__main__":
    data = load_data("enterprise-attack-v13.1.json")
    
    # Define your queries here (key-value pairs with default None)
    queries = {
        "ID": None,
        "name": None,
        "description": None,
        "url": None,
        "created": None,
        "last modified": None,
        "version": None,
        "tactics": None,
        "detection": None,
        "platforms": "Windows",
        "data sources": None,
        "is sub-technique": None,
        "sub-technique of": None,
        "defenses bypassed": "Anti-virus, Application Control, File monitoring, Host intrusion prevention systems, System Access Controls, Signature-based detection",
        "contributors": None,
        "permissions required": "User",
        "supports remote": None,
        "system requirements": None,
        "impact type": None,
        "effective permissions": None,
        "relationship": None
    }

    # Update the query values as needed
    # Example: queries["platforms"] = "Windows"

    results = query_data(data, queries)

    # Print results
    for item in results:
        print(item)

