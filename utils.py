import os
import json
import gzip
import csv
import requests
import boto3
from botocore.exceptions import ClientError

# Load EPSS scores and return a mapping: CVE-ID -> {score, percentile}
def load_epss_scores():
    print("⬇️  Loading EPSS scores...")
    url = "https://www.first.org/epss/data/epss_scores-current.csv.gz"
    print("⬇️  Fetching EPSS CSV feed...")
    r = requests.get(url)
    r.raise_for_status()

    epss_map = {}
    with gzip.open(io.BytesIO(r.content), mode='rt', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            epss_map[row["cve"]] = {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"])
            }
    return epss_map

# Decide whether to skip uploading if the file already exists in R2
def should_upload(s3, bucket_name, key):
    try:
        s3.head_object(Bucket=bucket_name, Key=key)
        return False  # already exists
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return True  # does not exist
        raise

# Inject EPSS into CVE JSON
def enrich_cve_item(cve_data, epss_map):
    cve_id = cve_data.get("cve", {}).get("CVE_data_meta", {}).get("ID")
    epss_info = epss_map.get(cve_id)

    if epss_info:
        cve_data["epss"] = {
            "score": epss_info["score"],
            "percentile": epss_info["percentile"]
        }

    return cve_data

# Setup boto3 S3 client
def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{os.environ['CF_ACCOUNT_ID']}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"]
    )
