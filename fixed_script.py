import json
from pathlib import Path
import faiss
from sentence_transformers import SentenceTransformer
import numpy as np

# Load data from a JSON file specified by file_path
def load_data(file_path):
    with open(file_path, 'r') as f:
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

def search_top_k(platform, query, model, top_k=5):
    index = get_faiss_index(platform)
    if index is None:
        return None, None

    query_vec = model.encode([query], convert_to_tensor=True, normalize_embeddings=True).cpu().detach().numpy()
    similarities, indices = index.search(query_vec, top_k)

    return similarities, indices

# Update threats in the source data based on entity platforms and similarity to threat data
def update_threats_for_entities(source_data, model, threat_data):

    # Pre-load FAISS indexes to optimize search performance
    platform_indexes = {
        "Azure AD": get_faiss_index("Azure AD"),
        "Containers": get_faiss_index("Containers"),
        "Google Workspace": get_faiss_index("Google Workspace"),
        "IaaS": get_faiss_index("IaaS"),
        "Linux": get_faiss_index("Linux"),
        "macOS": get_faiss_index("macOS"),
        "Network": get_faiss_index("Network"),
        "Office 365": get_faiss_index("Office 365"),
        "PRE": get_faiss_index("PRE"),
        "SaaS": get_faiss_index("SaaS"),
        "Windows": get_faiss_index("Windows"),
    }

    # Iterate into each entity within threat dragon json, detail -> cells -> data (Entity is here)
    for diagram in source_data.get('detail', {}).get('diagrams', []):
        if 'cells' in diagram:
            for cell in diagram['cells']:
                if 'data' in cell:
                    data = cell['data']
                    if 'platforms' in data:
                        # Extract the platforms associated with the entity
                        platforms = data['platforms'].split(', ')
                        print(f"Processing entity with platforms: {platforms}")
                        
                        # Iterate over each platform associated with the entity
                        for platform in platforms:
                            # Check if there is a pre-loaded FAISS index for the platform
                            if platform in platform_indexes:
                                # Get the FAISS index for the platform
                                index = platform_indexes[platform]

                                # Convert the entity's data into a query string for similarity search
                                query = entity_to_query_string(cell)


                                # Perform a FAISS search to find the most similar threats
                                distances, indices = search_top_k(platform, query, model)

                                # Check if the search was successful
                                if distances is not None and indices is not None and indices.size > 0:
                                    threats = []
                                    # Iterate over the indices of the most similar threats
                                    for idx in indices[0]:
                                        # Get the actual threat data using the index
                                        threat = threat_data[idx]
                                        # Append the threat ID to the threats list
                                        threats.append(threat)
                                    # Update the entity's data with the found threats
                                    data['threats'].extend(threats)
                                    print(f"Threats appended successfully for platform {platform}!")
                                else:
                                    print(f"No threats found above the threshold for platform {platform}")


    # Return the source data with updated threats
    return source_data


# Main function to execute the threat update process
def main():
    source_data_file_path = "threatdragon_blank.json"
    threat_data_file_path = "data.json"
    model = SentenceTransformer("all-mpnet-base-v2")

    source_data = load_data(source_data_file_path)
    threat_data = load_data(threat_data_file_path)

    updated_data = update_threats_for_entities(source_data, model, threat_data)

    with open('updated_threatdragon.json', 'w') as updated_file:
        json.dump(updated_data, updated_file, indent=4)

    print("Threats updated successfully!")

# Execute the script
if __name__ == "__main__":
    main()
