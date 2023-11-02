import json
import os
import traceback
import boto3

# Initialize an S3 client
s3 = boto3.client('s3')

def load_db_data():
    file_path = os.path.join(os.path.dirname(__file__), "data.json")
    with open(file_path, 'r', encoding='utf-8-sig') as f:
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

def lambda_handler(event, context):
    try:
        # Load threat dragon data from the HTTP request body
        threat_dragon_data = json.loads(event.get("body", "{}"))
        
        # Load the threat database from the Lambda's file system
        db_data = load_db_data()

        # Process the threat dragon data
        enriched_data = update_threats_for_entities(threat_dragon_data, db_data)

        # Check if the enriched data is too large to send in response
        enriched_data_str = json.dumps(enriched_data)
        if len(enriched_data_str) > 8 * 1024 * 1024:  # 8 MB (keeping it lower than 10 MB to be safe)
            # Save the enriched data to S3
            bucket_name = "your-s3-bucket-name"
            file_key = "path/to/enriched_data.json"
            s3.put_object(Body=enriched_data_str, Bucket=bucket_name, Key=file_key)

            # Generate a pre-signed URL for the S3 object
            presigned_url = s3.generate_presigned_url('get_object',
                                                      Params={'Bucket': bucket_name, 'Key': file_key},
                                                      ExpiresIn=3600)  # URL expires in 1 hour

            # Return the pre-signed URL
            return {
                "statusCode": 200,
                "body": json.dumps({"url": presigned_url}),
                "headers": {
                    "Content-Type": "application/json"
                }
            }
        else:
            # Return the enriched data directly
            return {
                "statusCode": 200,
                "body": enriched_data_str,
                "headers": {
                    "Content-Type": "application/json"
                }
            }
    except Exception as e:
        error_message = str(e)
        error_traceback = traceback.format_exc()
        print(error_traceback)  # This will log the full traceback to CloudWatch
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error_message": error_message,
                "error_traceback": error_traceback
            }),
            "headers": {
                "Content-Type": "application/json"
            }
        }
