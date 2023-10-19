
import json

# File paths
source_data_file_path = "threatdragon_blank.json"
db_data_file_path = "data.json"

def load_data(filename):
    with open(filename, 'r', encoding='utf-8-sig') as f:
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

if __name__ == "__main__":
    source_data = load_data(source_data_file_path)
    db_data = load_data(db_data_file_path)

    updated_data = update_threats_for_entities(source_data, db_data)
    
    with open('updated_threatdragon.json', 'w') as updated_file:
        json.dump(updated_data, updated_file, indent=4)
    
    print(f"Threats updated successfully!")
