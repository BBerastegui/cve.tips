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

def enrich_cve_item(cve_data, epss_map):
    cve_id = cve_data.get("cve", {}).get("CVE_data_meta", {}).get("ID")
    epss_info = epss_map.get(cve_id)
    if epss_info:
        cve_data["epss"] = {
            "score": epss_info["score"],
            "percentile": epss_info["percentile"]
        }
    return cve_data

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
    import requests, csv, gzip
    from io import BytesIO, TextIOWrapper

    print("⬇️  Fetching EPSS CSV feed...")
    url = "https://epss.cybertrust.nist.gov/epss_scores-current.csv.gz"
    r = requests.get(url)
    r.raise_for_status()

    buf = BytesIO(r.content)
    with gzip.open(buf, mode='rt') as f:
        reader = csv.DictReader(f)
        return {
            row["cve"]: {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"])
            }
            for row in reader
        }
