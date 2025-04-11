import sys
import argparse
import os
import json
import threading
from datetime import date

# import time

import subprocess
from google.cloud import pubsub_v1
from bibt.gcp import storage

# from bibt.gcp import storage
from healthcheck import run_health_server, set_ready


def nmap_host(message):
    # message = {
    #   "network": "projects/123456789/global/networks/default", # pragma: allowlist secret # noqa
    #   "ips": ["1.2.3.4","4.4.4.4"],
    #   "ports": ["1-122","49","8000-9000"],
    # }
    try:
        message.ack()
        data = json.loads(message.data.decode("utf-8"))
        network = data["network"]
        ips = data["ips"]
        ports = data["ports"]

        results_outfile = "/tmp/results.xml"
        if ports == "1-65535":
            print(f"Running reduced-intensity nmap scan on {network} | {ips} | {ports}")
            result = subprocess.run(
                [
                    "nmap",
                    " ".join(ips),
                    "-p",
                    ",".join(ports),
                    "-Pn",
                    "-T4",
                    "sS",
                    "--stats-every",
                    "10m",
                    "-sV",
                    "--version-intensity",
                    "2",
                    "-oX",
                    results_outfile,
                ],
                capture_output=True,
                text=True,
            )
        else:
            print(f"Running full-intensity nmap scan on {network} | {ips} | {ports}")
            result = subprocess.run(
                [
                    "nmap",
                    " ".join(ips),
                    "-p",
                    ",".join(ports),
                    "-Pn",
                    "-T4",
                    "sS",
                    "--stats-every",
                    "10m",
                    "-sV",
                    "--version-intensity",
                    "8",
                    "-oX",
                    results_outfile,
                ],
                capture_output=True,
                text=True,
            )
        print("Scan complete. stdout:")
        print(result.stdout)

        print("Uploading results to GCS...")
        storage_client = storage.Client()
        results_blob_name = (
            f"{date.today().isoformat()}/{network.replace('/', '.')}.scan-results.xml"
        )
        storage_client.write_gcs_from_file(
            os.environ["GCS_BUCKET"],
            results_blob_name,
            results_outfile,
            mime_type="application/xml",
        )
        print(
            f"Scan results written to gs://{os.environ['GCS_BUCKET']}"
            f"/{results_blob_name}"
        )

    except Exception as e:
        print(f"Scan failed: {e}")


def main(config):
    subscription_project = config["subscription-project"]
    subscription_topic = config["subscription-topic"]
    if not os.environ.get("GCS_BUCKET"):
        os.environ["GCS_BUCKET"] = config["gcs-bucket"]
    if not os.environ.get("HTTP_SCANNER_TOPIC_URI"):
        os.environ["HTTP_SCANNER_TOPIC_URI"] = config["http-scanner-topic-uri"]

    subscriber = pubsub_v1.SubscriberClient()
    sub_path = subscriber.subscription_path(subscription_project, subscription_topic)
    set_ready(True)
    streaming_pull_future = subscriber.subscribe(sub_path, callback=nmap_host)
    print(f"Listening on Pub/Sub: {sub_path}")

    with subscriber:
        try:
            streaming_pull_future.result()
        except Exception as e:
            print(f"Listening for messages on {sub_path} threw an exception: {e}.")
            streaming_pull_future.cancel()
            streaming_pull_future.result()


def get_config():
    parser = argparse.ArgumentParser(
        description=(
            "Values passed via CLI will take precedence over environment variables."
        )
    )

    parser.add_argument(
        "--gcs-bucket",
        type=str,
        help=(),
        required=False,
    )
    parser.add_argument(
        "--subscription-project",
        type=str,
        help=(),
        required=False,
    )
    parser.add_argument(
        "--subscription-topic",
        type=str,
        help=(),
        required=False,
    )
    parser.add_argument(
        "--http-scanner-topic-uri",
        type=str,
        help=(),
        required=False,
    )

    args = parser.parse_args()

    config = {
        "gcs-bucket": args.gcs_bucket or os.environ.get("GCS_BUCKET"),
        "subscription-project": args.subscription_project
        or os.environ.get("SUBSCRIPTION_PROJECT"),
        "subscription-topic": args.subscription_topic
        or os.environ.get("SUBSCRIPTION_TOPIC"),
        "http-scanner-topic-uri": args.http_scanner_topic_uri
        or os.environ.get("HTTP_SCANNER_TOPIC_URI"),
    }

    if (
        not config["subscription-project"]
        or not config["subscription-topic"]
        or not config["gcs-bucket"]
    ):
        print("ERROR: Missing required arguments.")
        print(
            "Please provide --subscription-project and --subscription-topic or set "
            "the GCS_BUCKET and GCP_ORG_ID environment variables."
        )
        parser.print_help()
        sys.exit(1)

    return config


if __name__ == "__main__":
    # Start the health server in the background
    threading.Thread(target=run_health_server, daemon=True).start()
    config = get_config()
    main(config)
