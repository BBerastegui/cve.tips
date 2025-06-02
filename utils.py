import os
import json
import csv
import boto3
import requests
from io import StringIO

R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET = os.environ.get("R2_BUCKET")
R2_ENDPOINT_URL = os.environ.get("R2_ENDPOINT_URL")

s3 = boto3.client(
    "s3",
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    endpoint_url=R2_ENDPOINT_URL,
)

def upload_to_r2(key, data):
    s3.put_object(
        Bucket=R2_BUCKET,
        Key=key,
        Body=json.dumps(data),
        ContentType="application/json"
    )

def get_existing_object(key):
    try:
        result = s3.get_object(Bucket=R2_BUCKET, Key=key)
        return json.load(result["Body"])
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return None
        raise

def load_epss_scores():
    print("⬇️  Fetching EPSS CSV feed...")
    url = "https://www.first.org/epss/data/epss_scores-current.csv.gz"
    r = requests.get(url)
    r.raise_for_status()

    data = r.content
    scores = {}
    with gzip.open(StringIO(data.decode()), mode='rt') as f:
        reader = csv.DictReader(filter(lambda row: not row.startswith('#'), f))
        for row in reader:
            scores[row["cve"]] = {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"])
            }
    print(f"✅ Loaded {len(scores)} EPSS entries")
    return scores
