from datetime import datetime
import sys
#print(datetime.now(), "Import Started from: ", sys.path)
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from pathlib import Path
#print(datetime.now(), "Import completed.")

root_path = "/hostdata/"
encoder = SentenceTransformer("all-mpnet-base-v2")

def max_words(strings):
    maxwords = 0
    # Loop through each string in the list
    for string in strings:
      # Count the number of words in the current string
      words = len(set(string.split()))
      # If the number of words is greater than the current maximum, update the maximum
      if words > maxwords:
        maxwords = words
    return maxwords
    
def get_enterprise_json():
    ent_json_filepath = root_path + "enterprise-attack.json"
    with open(ent_json_filepath, "r") as f:
        # Load the JSON data from the file
        data = json.load(f)
    return data

def parse_enterprise_json_for_platform(platform, data):
    # Extract the techniques from the JSON file (exclude depricated and revoked)
    techniques = [obj for obj in data["objects"] if obj["type"] == "attack-pattern"  and obj.get("x_mitre_deprecated",False) != True and obj.get("revoked",False) != True and platform in obj.get("x_mitre_platforms",[])]

    # Extract the techniques and mitigations from the JSON file (exclude depricated and revoked)
    mitigations = [obj for obj in data["objects"] if obj["type"] == "course-of-action"  and obj.get("x_mitre_deprecated",False) != True and obj.get("revoked",False) != True]

    # Extract the relationships between techniques and mitigations from the JSON file
    relations = [obj for obj in data["objects"] if obj["type"] == "relationship" and obj["relationship_type"] == "mitigates"]

    #print(datetime.now(), "Found " + str(len(techniques)) + " techniques, " + str(len(mitigations)) + " mitigations and " + str(len(relations)) + " relations.")

    # Create a mapping from technique ID to mitigation IDs
    tech_to_mit = {}
    for tech in techniques:
        tech_id = tech["id"]
        mit_ids = []
        for rel in relations:
            if rel["target_ref"] == tech_id:
                mit_ids.append(rel["source_ref"])
        if len(mit_ids) > 0:
            tech_to_mit[tech_id] = mit_ids

    #print(datetime.now(), "Mapped mitigations for " + str(len(tech_to_mit)) + " techniques.")

    # Create a mapping from mitigation ID to mitigation name and description
    mit_to_info = {}
    for mit in mitigations:
        mit_id = mit["id"]
        mit_ext_id = mit["external_references"][0]["external_id"]
        mit_name = mit["name"]
        mit_desc = mit["description"]
        mit_to_info[mit_id] = (mit_ext_id, mit_name, mit_desc)

    return techniques, tech_to_mit, mit_to_info


def get_faiss_index(platform):
    faiss_index_path = root_path + platform + "_FAISS_Index.bin"
    if Path(faiss_index_path).exists():
        #print(datetime.now(), "Found index file ", faiss_index_path)
        index = faiss.read_index(faiss_index_path)
    else:
        #print(datetime.now(), "Index file ", faiss_index_path, " doesn't exist")
        data = get_enterprise_json()
        techniques = [obj for obj in data["objects"] if obj["type"] == "attack-pattern"  and obj.get("x_mitre_deprecated",False) != True and obj.get("revoked",False) != True and platform in obj.get("x_mitre_platforms",[])]

        # Create a list of technique names and descriptions
        texts = [tech["name"] + ": " + tech["description"] + ",".join(tech.get("x_mitre_data_sources",[])) + ",".join(tech.get("x_mitre_permissions_required",[])) for tech in techniques]
        #texts = [tech["name"] + ": " + ",".join(tech.get("x_mitre_platforms",[])) + ",".join(tech.get("x_mitre_data_sources",[])) + ",".join(tech.get("x_mitre_permissions_required",[])) for tech in techniques]
        #print(datetime.now(), "Created " + str(len(texts)) + " texts.")
        
        maxWords = max_words(texts)
        #print(datetime.now(), "Max words: " + str(maxWords) + " but encoder max sequence length is " + str(encoder.max_seq_length))
        
        if maxWords > 512:
            encoder.max_seq_length = 512
        else:
            encoder.max_seq_length = maxWords
        #print(datetime.now(), "Adjusted encoder max sequence length to " + str(encoder.max_seq_length))

        # Encode the techniques into vectors
        encoded_texts = encoder.encode(texts)
        #print(datetime.now(), "Created " + str(len(encoded_texts)) + " encoded_texts.")

        # Creat a FAISS index for the encoded techniques
        vector_dimension = encoded_texts.shape[1]
        #index = faiss.IndexFlatL2(vector_dimension)
        #faiss.normalize_L2(encoded_texts)
        #index.add(encoded_texts)

        index = faiss.IndexIDMap(faiss.IndexFlatIP(vector_dimension))
        faiss.normalize_L2(encoded_texts)
        index.add_with_ids(encoded_texts, np.array(range(0, len(encoded_texts))))
        
        # Write the index to store for re-use
        faiss.write_index(index, faiss_index_path)
        #print(datetime.now(), "Index file created")
    return index

# returns top n threats
def search_count_limited(platform, max_count, search_text):
    index = get_faiss_index(platform)
    # Encode query
    encoded_query = encoder.encode(search_text)
    query_vector = np.array([encoded_query])
    faiss.normalize_L2(query_vector)

    # Search the index for similar techniques
    scores, indices = index.search(query_vector, max_count) # Get top most similar techniques
    #limits, scores, indices = index.range_search(query_vector, 0.45) # Get similar techniques whose score is greater than a threshold
    scores = scores.flatten()
    indices = indices.flatten()
    return scores, indices

# returns top threats above a threshold
def search_score_limited(platform, min_score, search_text):
    index = get_faiss_index(platform)
    # Encode query
    encoded_query = encoder.encode(search_text)
    query_vector = np.array([encoded_query])
    faiss.normalize_L2(query_vector)

    # Search the index for similar techniques
    #scores, indices = index.search(query_vector, max_count) # Get top most similar techniques
    limits, scores, indices = index.range_search(query_vector, min_score) # Get similar techniques whose score is greater than a threshold
    scores = scores.flatten()
    indices = indices.flatten()
    return scores, indices

def find_threats_count_based(platform, max_count, query):
    data = get_enterprise_json()
    techniques, tech_to_mit, mit_to_info = parse_enterprise_json_for_platform(platform, data)
    scores, indices = search_count_limited(platform, max_count, query)
    results = []
    for score, idx in zip(scores, indices):
        # Get the technique ID
        tech_id = techniques[idx]["id"]
        # Get the mitigation IDs from the mapping
        mit_ids = tech_to_mit.get(tech_id,[])
        # Get the mitigation names and descriptions from the mapping
        mits = []
        for mit_id in mit_ids:
            mit_ext_id, mit_name, mit_desc = mit_to_info[mit_id]
            mits.append({"ID": mit_ext_id, "name": mit_name, "description": mit_desc})
        sorted_mits = sorted (mits, key=lambda x: x["ID"])
        results.append({"ID": techniques[idx]["external_references"][0]["external_id"],"name": techniques[idx]["name"], "description": techniques[idx]["description"], "score": score, "mitigations": sorted_mits})
    return results

def find_threats_score_based(platform, min_score, query):
    data = get_enterprise_json()
    techniques, tech_to_mit, mit_to_info = parse_enterprise_json_for_platform(platform, data)
    scores, indices = search_score_limited(platform, min_score, query)
    results = []
    for score, idx in zip(scores, indices):
        # Get the technique ID
        tech_id = techniques[idx]["id"]
        # Get the mitigation IDs from the mapping
        mit_ids = tech_to_mit.get(tech_id,[])
        # Get the mitigation names and descriptions from the mapping
        mits = []
        for mit_id in mit_ids:
            mit_ext_id, mit_name, mit_desc = mit_to_info[mit_id]
            mits.append({"ID": mit_ext_id, "name": mit_name, "description": mit_desc})
        sorted_mits = sorted (mits, key=lambda x: x["ID"])
        results.append({"ID": techniques[idx]["external_references"][0]["external_id"],"name": techniques[idx]["name"], "description": techniques[idx]["description"], "score": score, "mitigations": sorted_mits})
    return results



mitre_platforms = "Android, Azure AD, Containers, Engineering Workstation, Field Controller/RTU/PLC/IED, Google Workspace, IaaS, Linux, Network, Office 365, PRE, SaaS, Windows, iOS, macOS"


#print(datetime.now(), "Search started.")
search_text = 'Process, MIPSA Web Application, Linux Containers, Access to files, Access to shared folders and content with write permissions, User, Administrator, System, Application Log, Command, Container, Process, Service, Web Credential, Logon Session, Instance'

#search_text = 'Store, TMT Database, Oracle Database, Linux, User, Application Log, Logon Session'

#search_text = 'Store, MIPSA NoSQL Database, NoSQL Database, Linux, User, Application Log, Logon Session'

#search_text = 'Actor, USCG iPad, United States Coast Guard, iPad Tablet, iOS, Valid domain account User Kerberos authentication enabled, User, Administrator, User Account'

max_count = 5
min_score = 0.4 # should be between 0 and 1
platforms = ["Linux","Containers"]

for platform in platforms:
    #results = find_threats_count_based (platform, max_count, search_text)
    results = find_threats_score_based (platform, min_score, search_text)

    print("Platform: ", platform, " Search Text: ", search_text)
    for result in results:
        print("----------------------------------------------------------------------------------------------")
        print("Attack Name: ", result["ID"], ": ", result["name"],"(Similarity: ", result["score"], ")")
        print("Attack Description: ", result["description"])
        #print("Similarity: ", result["score"])
        print("Mitigations: ")
        for mit in result["mitigations"]:
            print("- " + mit["ID"] + ": " + mit["name"] + ": " + mit["description"])
            #print("- " + mit["ID"] + ": " + mit["name"])
            #print()
        print()
