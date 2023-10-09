import pandas as pd
import json

def csv_to_json():
    # Specify the file paths here
    input_file = "input.csv"
    output_file = "output.json"

    # Read the CSV file using pandas
    df = pd.read_csv(input_file)

    # Convert the columns 'platforms', 'defenses bypassed', and 'permissions required' to lists
    for col in ['platforms', 'defenses bypassed', 'permissions required']:
        df[col] = df[col].str.split(',').apply(lambda x: [item.strip() for item in x] if isinstance(x, list) else x)

    # Replace NaN values with None (which becomes 'null' in JSON)
    df = df.where(pd.notna(df), None)

    # Convert dataframe to JSON format
    json_data = df.to_dict(orient='records')

    # Write JSON data to output file
    with open(output_file, 'w') as json_file:
        json.dump(json_data, json_file, indent=4)

if __name__ == "__main__":
    csv_to_json()
    print("Conversion completed.")
