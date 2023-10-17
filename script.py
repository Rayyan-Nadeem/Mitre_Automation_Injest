import pandas as pd
import json

# File paths
source_data_file_path = "MIPSA TM Blank.json"
db_data_file_path = "enterprise-attack-v13.1.json"
query_file_path = "param.json"

def load_data(filename):
    with open(filename, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def append_threat_to_entity(source_data, entity_id, threats):
    for diagram in source_data.get('detail', {}).get('diagrams', []):
        for cell in diagram.get('cells', []):
            if cell.get('id') == entity_id:
                cell_data = cell.get('data', {})
                current_threats = cell_data.get('threats', [])
                current_threats.extend(threats)
                cell_data['threats'] = current_threats
                break
    return source_data

def query_data(data, queries):
    results = []
    matched_ids = set()
    for key, value in queries.items():
        if isinstance(value, str) and ',' in value:
            queries[key] = [v.strip() for v in value.split(',')]
    for item in data:
        match = True
        for key, value in queries.items():
            item_values = item.get(key, []) or []
            if not value:
                continue
            elif not item_values:
                continue
            elif isinstance(value, list):
                if not any(v in item_values for v in value):
                    match = False
                    break
            elif isinstance(item_values, list):
                if not any(value in v for v in item_values):
                    match = False
                    break
            elif item.get(key) != value:
                match = False
                break
        if match and item['ID'] not in matched_ids:
            results.append(item)
            matched_ids.add(item['ID'])
    return results


if __name__ == "__main__":
    source_data = load_data(source_data_file_path)
    db_data = load_data(db_data_file_path)
    threat_query = load_data(query_file_path)

    entity_id = threat_query.pop("EntityID")
    filtered_techniques = query_data(db_data, threat_query)

    # Convert the filtered techniques into a DataFrame
    df = pd.DataFrame(filtered_techniques)
    print(df)

