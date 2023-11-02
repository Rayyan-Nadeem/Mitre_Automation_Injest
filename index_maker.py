import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from pathlib import Path
from typing import List, Dict

def max_words(strings: List[str]) -> int:
    maxwords = 0
    for string in strings:
        words = len(set(string.split()))
        if words > maxwords:
            maxwords = words
    return maxwords

def get_faiss_index_for_platform(platform: str, texts: List[str]):
    faiss_index_path = root_path + platform + "_Index.bin"
    maxWords = max_words(texts)
    if maxWords > 512:
        encoder.max_seq_length = 512
    else:
        encoder.max_seq_length = maxWords
    
    encoded_texts = encoder.encode(texts)
    vector_dimension = encoded_texts.shape[1]
    index = faiss.IndexIDMap(faiss.IndexFlatIP(vector_dimension))
    faiss.normalize_L2(encoded_texts)
    index.add_with_ids(encoded_texts, np.array(range(0, len(encoded_texts))))
    faiss.write_index(index, faiss_index_path)

def organize_data_by_platform(data: List[Dict]) -> Dict[str, List[str]]:
    platform_to_texts = {}
    
    for threat in data:
        # Specify the fields you want to include in the text descriptions
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
            platform_to_texts[platform].append(text)
    
    return platform_to_texts


def create_faiss_indices(data_json_path: str, root_path: str):
    with open(data_json_path, "r") as f:
        data = json.load(f)
    platform_to_texts = organize_data_by_platform(data)
    for platform, texts in platform_to_texts.items():
        get_faiss_index_for_platform(platform, texts)
        print(f"FAISS index for {platform} is created and saved at {root_path + platform + '_Index.bin'}\n")
    print("All FAISS index files are created and saved!")

def main():
    directory_path = "C:/Users/Rayyan/Mitre_Automation_Injest"
    global root_path
    root_path = directory_path + "/index_bin/"
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    global encoder
    encoder = SentenceTransformer("all-mpnet-base-v2")
    data_json_path = directory_path + "/data.json"
    create_faiss_indices(data_json_path, root_path)

if __name__ == "__main__":
    main()
