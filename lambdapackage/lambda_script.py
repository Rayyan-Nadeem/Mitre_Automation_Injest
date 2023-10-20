import json

def load_db_data():
    with open("data.json", 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def filter_threats_by_platform(db_data, platforms):
    filtered_threats = []
    for item in db_data:
        item_platforms = item.get("platforms", [])
        if isinstance(item_platforms, str):
            item_platforms = [item_platforms]
        if any(platform.lower() in [ip.lower() for ip in item_platforms] for platform in platforms):
            filtered_threats.append(item)
    return filtered_threats

def update_threats_for_entities(source_data, db_data):
    diagrams = source_data.get('detail', {}).get('diagrams', [])
    for diagram in diagrams:
        for cell in diagram.get('cells', []):
            cell_data = cell.get('data', {})
            platforms = cell_data.get('platforms', '').split(', ')
            filtered_threats = filter_threats_by_platform(db_data, platforms)
            current_threats = cell_data.get('threats', [])
            current_threats.extend(filtered_threats)
            cell_data['threats'] = current_threats
    return source_data

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")

    try:
        # Load threat dragon data from the request body
        threat_dragon_data = json.loads(event.get("body", "{}"))

        
        # Load the threat database from the Lambda's file system
        db_data = load_db_data()

        # Process the threat dragon data
        enriched_data = update_threats_for_entities(threat_dragon_data, db_data)
        print(f"Received input of size: {len(json.dumps(threat_dragon_data))} bytes")

        # Return the enriched data
        return {
            "statusCode": 200,
            "body": json.dumps(enriched_data),
            "headers": {
                "Content-Type": "application/json"
            }
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": str(e),
            "headers": {
                "Content-Type": "text/plain"
            }
        }
