import pandas as pd
import json

def load_data(filename):
    with open(filename, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def query_data(data, queries):
    results = []
    matched_ids = set()  # Track IDs of matched techniques to prevent duplicates

    # Convert comma-separated string values to lists for "match any" behavior
    for key, value in queries.items():
        if isinstance(value, str) and ',' in value:
            queries[key] = [v.strip() for v in value.split(',')]

    # Find matching techniques based on queries
    for item in data:
        match = True
        for key, value in queries.items():
            item_values = item.get(key, []) or []
            if not value:  # If the query value is None or empty, it's a wildcard match
                continue
            elif not item_values:  # If the item value is None or empty, it's applicable to all
                continue
            elif isinstance(value, list):  # Special handling for "match any" behavior
                if not any(v in item_values for v in value):  # Check if any of the query values match
                    match = False
                    break
            elif isinstance(item_values, list):  # For fields with list values
                if not any(value in v for v in item_values):  # Check for partial matches within the list
                    match = False
                    break
            elif item.get(key) != value:  # For fields with string values
                match = False
                break

        if match and item['ID'] not in matched_ids:
            results.append(item)
            matched_ids.add(item['ID'])
            
    return results

# Additional function to load the queries from param.json
def load_queries(filename):
    with open(filename, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

# Updated main block to use the load_queries function
if __name__ == "__main__":
    data = load_data("enterprise-attack-v13.1.json")
    
    # Load your queries from param.json
    queries = load_queries("param.json")

    # Execute the query and get the results
    results = query_data(data, queries)
    
    # Convert results to a DataFrame and save to a CSV
    df = pd.DataFrame(results)
    df.to_csv("query_results.csv", index=False)

    # Print results
    print(df)
