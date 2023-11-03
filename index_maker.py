import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict

def max_words(strings: List[str]) -> int:
    maxwords = 0
    for string in strings:
        words = len(set(string.split()))
        if words > maxwords:
            maxwords = words
    return maxwords

def get_faiss_index_for_platform(platform: str, texts_and_ids: List[tuple], root_path: str, encoder: SentenceTransformer):
    faiss_index_path = os.path.join(root_path, platform + "_Index.bin")
    mapping_path = os.path.join(root_path, platform + "_Mapping.json")
    
    texts, threat_ids = zip(*texts_and_ids)  # Unpack the list of tuples
    maxWords = max_words(texts)
    encoder.max_seq_length = min(maxWords, 512)
    
    encoded_texts = encoder.encode(texts)
    vector_dimension = encoded_texts.shape[1]
    index = faiss.IndexIDMap(faiss.IndexFlatIP(vector_dimension))
    faiss.normalize_L2(encoded_texts)

    # Generate numerical IDs for FAISS index
    numerical_ids = np.arange(len(threat_ids))
    index.add_with_ids(encoded_texts, numerical_ids)

    # Create a mapping between numerical IDs and threat IDs
    id_to_threat = {num_id: threat_id for num_id, threat_id in enumerate(threat_ids)}

    with open(mapping_path, 'w') as f_map:
        json.dump(id_to_threat, f_map, indent=4)
    
    faiss.write_index(index, faiss_index_path)


def organize_data_by_platform(data: List[Dict]) -> Dict[str, List[tuple]]:
    platform_to_texts = {}
    
    for threat in data:
        fields = ['name', 'detection', 'tactics', 'description', 'permissions_required', 'defenses_bypassed', 'data_sources']
        text_parts = []
        for field in fields:
            value = threat.get(field, "")
            if isinstance(value, list):
                value = ",".join(map(str, value))
            elif isinstance(value, dict):
                value = str(value)
            text_parts.append(f"{field}: {value}")
        text = ", ".join(text_parts)
        
        for platform in threat.get("platforms", []):
            if platform not in platform_to_texts:
                platform_to_texts[platform] = []
            platform_to_texts[platform].append((text, threat['id']))
    
    return platform_to_texts

def create_faiss_indices(data_json_path: str, root_path: str, encoder):
    with open(data_json_path, "r") as f:
        data = json.load(f)

    platform_to_texts_and_ids = organize_data_by_platform(data)
    for platform, texts_and_ids in platform_to_texts_and_ids.items():
        try:
            get_faiss_index_for_platform(platform, texts_and_ids, root_path, encoder)
            print(f"FAISS index for {platform} is created and saved at {root_path + platform + '_Index.bin'}")
            print(f"Mapping for {platform} is created and saved at {root_path + platform + '_Mapping.json'}\n")
        except Exception as e:
            print(f"An error occurred while creating the index for {platform}: {e}")
    
    print("All FAISS index files and mappings are created and saved!")

def main():
    directory_path = "C:/Users/Rayyan/Mitre_Automation_Injest"
    root_path = os.path.join(directory_path, "index_bin")
    os.makedirs(root_path, exist_ok=True)
    encoder = SentenceTransformer("all-mpnet-base-v2")
    data_json_path = os.path.join(directory_path, "data.json")
    create_faiss_indices(data_json_path, root_path, encoder)

if __name__ == "__main__":
    main()
