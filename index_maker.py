import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict

# Function to find the maximum number of words in a list of strings
def max_words(strings: List[str]) -> int:
    maxwords = 0
    for string in strings:
        words = len(set(string.split()))  # Split the string into words and count unique words
        if words > maxwords:
            maxwords = words
    return maxwords

# Function to create a FAISS index for a specific platform
def get_faiss_index_for_platform(platform: str, texts_and_ids: List[tuple], root_path: str, encoder: SentenceTransformer):
    faiss_index_path = os.path.join(root_path, platform + "_Index.bin")  # Define the path for the FAISS index file
    mapping_path = os.path.join(root_path, platform + "_Mapping.json")  # Define the path for the mapping file
    
    texts, threat_ids = zip(*texts_and_ids)  # Unpack the list of tuples into separate lists of texts and threat IDs
    maxWords = max_words(texts)  # Get the maximum number of words in the list of texts
    encoder.max_seq_length = min(maxWords, 512)  # Set the maximum sequence length for the encoder
    
    encoded_texts = encoder.encode(texts)  # Encode the texts using the Sentence Transformer model
    vector_dimension = encoded_texts.shape[1]  # Get the dimension of the encoded vectors
    index = faiss.IndexIDMap(faiss.IndexFlatIP(vector_dimension))  # Create a FAISS index with Inner Product (IP) similarity
    faiss.normalize_L2(encoded_texts)  # Normalize the encoded vectors
    
    # Generate numerical IDs for FAISS index
    numerical_ids = np.arange(len(threat_ids))
    index.add_with_ids(encoded_texts, numerical_ids)  # Add the encoded vectors to the FAISS index along with numerical IDs

    # Create a mapping between numerical IDs and threat IDs
    id_to_threat = {num_id: threat_id for num_id, threat_id in enumerate(threat_ids)}

    with open(mapping_path, 'w') as f_map:
        json.dump(id_to_threat, f_map, indent=4)  # Save the mapping between numerical IDs and threat IDs to a JSON file
    
    faiss.write_index(index, faiss_index_path)  # Save the FAISS index to a binary file

# Function to organize data by platform
def organize_data_by_platform(data: List[Dict]) -> Dict[str, List[tuple]]:
    platform_to_texts = {}  # Create an empty dictionary to store data organized by platform
    
    for threat in data:
        fields = ['name', 'detection', 'tactics', 'description', 'permissions_required', 'defenses_bypassed', 'data_sources']
        text_parts = []
        
        # Create a textual representation of threat data by concatenating specific fields
        for field in fields:
            value = threat.get(field, "")
            if isinstance(value, list):
                value = ",".join(map(str, value))
            elif isinstance(value, dict):
                value = str(value)
            text_parts.append(f"{field}: {value}")
        
        text = ", ".join(text_parts)  # Join the textual parts with commas
        
        # Associate the text with each platform it is relevant to
        for platform in threat.get("platforms", []):
            if platform not in platform_to_texts:
                platform_to_texts[platform] = []  # Initialize a list for the platform if it doesn't exist
            platform_to_texts[platform].append((text, threat['id']))  # Append a tuple of text and threat ID
    
    return platform_to_texts

# Function to create FAISS indices for multiple platforms
def create_faiss_indices(data_json_path: str, root_path: str, encoder):
    with open(data_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)  # Load threat data from a JSON file

    platform_to_texts_and_ids = organize_data_by_platform(data)  # Organize threat data by platform
    for platform, texts_and_ids in platform_to_texts_and_ids.items():
        try:
            get_faiss_index_for_platform(platform, texts_and_ids, root_path, encoder)  # Create a FAISS index for each platform
            print(f"FAISS index for {platform} is created and saved at {root_path + platform + '_Index.bin'}")
            print(f"Mapping for {platform} is created and saved at {root_path + platform + '_Mapping.json'}\n")
        except Exception as e:
            print(f"An error occurred while creating the index for {platform}: {e}")
    
    print("All FAISS index files and mappings are created and saved!")

# Main function to orchestrate the process
def main():
    directory_path = "C:/Users/Rayyan/Mitre_Automation_Injest"
    root_path = os.path.join(directory_path, "index_bin")  # Define the root directory for saving FAISS index files
    os.makedirs(root_path, exist_ok=True)  # Create the root directory if it doesn't exist
    encoder = SentenceTransformer("all-mpnet-base-v2")  # Load a Sentence Transformer model
    data_json_path = os.path.join(directory_path, "data.json")  # Define the path to the input data JSON file
    create_faiss_indices(data_json_path, root_path, encoder)  # Create FAISS indices for the data

if __name__ == "__main__":
    main()  # Execute the main function when the script is run
