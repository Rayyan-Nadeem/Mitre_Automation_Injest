import json
from pathlib import Path
import faiss
from sentence_transformers import SentenceTransformer
import numpy as np

# Load data from a JSON file specified by file_path
def load_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

# Get the FAISS index for a specific platform, if it exists
def get_faiss_index(platform, root_path='index_bin/'):
    index_path = Path(root_path) / f"{platform}_Index.bin"
    if index_path.exists():
        index = faiss.read_index(str(index_path))
    else:
        print(f"Index file for {platform} does not exist!")
        index = None
    return index

# Convert an entity's data into a query string for similarity searching
def entity_to_query_string(entity):
    if "data" not in entity:
        return ""
    data = entity["data"]
    query_parts = [
        data.get("name", "").replace("\n", " "),
        data.get("description", ""),
        data.get("summary", ""),
        data.get("platforms", ""),
        data.get("permissions_required", ""),
        data.get("data_sources", ""),
        data.get("defenses_bypassed", "")
    ]
    query = ", ".join(query_parts)
    return query

# Perform similarity search and retrieve top-k threat IDs for a platform and query
def search_top_k(platform, query, model, top_k=5):
    index = get_faiss_index(platform)
    if index is None:
        return None, None
    query_vec = model.encode([query], convert_to_tensor=True, normalize_embeddings=True).cpu().detach().numpy()
    faiss.normalize_L2(query_vec)  # Normalize the query vector before searching
    D, I = index.search(query_vec, top_k)
    # Load the mapping
    mapping_path = 'index_bin/' + f"{platform}_Mapping.json"
    with open(mapping_path, 'r') as f_map:
        id_to_data = json.load(f_map)
    # Map FAISS indices to threat IDs
    threat_ids = [id_to_data[str(idx)] for idx in I[0] if str(idx) in id_to_data]
    return threat_ids

# Retrieve full threat information for a list of threat IDs from threat_data
def get_full_threat_info(threat_ids, threat_data):
    # Retrieve full threat information for each ID
    return [threat_data[threat_id] for threat_id in threat_ids if threat_id in threat_data]

# Update the 'threats' key in data with new threat information
def update_entity_threats(data, full_threat_info):
    # Ensure 'threats' key exists
    if 'threats' not in data:
        data['threats'] = []
    # Append new threat data if not already present
    for threat in full_threat_info:
        if threat not in data['threats']:
            data['threats'].append(threat)

# Update threats in the source data based on entity platforms and similarity to threat data
def update_threats_for_entities(source_data, model, threat_data):
    # Convert threat_data to a dictionary for quick access
    threat_data_dict = {threat['id']: threat for threat in threat_data}
    # Iterate through each entity and update threats
    for diagram in source_data.get('detail', {}).get('diagrams', []):
        if 'cells' in diagram:
            for cell in diagram['cells']:
                if 'data' in cell and 'platforms' in cell['data']:
                    data = cell['data']
                    platforms = data['platforms'].split(', ')
                    for platform in platforms:
                        query = entity_to_query_string(cell)
                        threat_ids = search_top_k(platform, query, model)
                        if threat_ids:
                            full_threat_info = get_full_threat_info(threat_ids, threat_data_dict)
                            update_entity_threats(data, full_threat_info)
                            print(f"Threats appended successfully for platform {platform}!")
                        else:
                            print(f"No threats found above the threshold for platform {platform}")
    return source_data

# Main function to execute the threat update process
def main():
    source_data_file_path = "threatdragon_blank.json"  # Path to the source data JSON file
    threat_data_file_path = "data.json"  # Path to the threat data JSON file
    model = SentenceTransformer("all-mpnet-base-v2")  # Load a Sentence Transformer model
    source_data = load_data(source_data_file_path)  # Load the source data
    threat_data = load_data(threat_data_file_path)  # Load the threat data
    updated_data = update_threats_for_entities(source_data, model, threat_data)  # Update threats in the source data
    with open('updated_threatdragon.json', 'w') as updated_file:
        json.dump(updated_data, updated_file, indent=4)  # Save the updated data to a JSON file
    print("Threats updated successfully!")

if __name__ == "__main__":
    main()  # Execute the main function when the script is run
