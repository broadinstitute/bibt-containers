import sys
import argparse
import os
import threading
from healthcheck import run_health_server, set_ready
from google.cloud import pubsub_v1
import requests
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json

from google.cloud import asset_v1
from bibt.gcp import iam
from fake_useragent import UserAgent
from google.cloud import logging as gcp_logging
from google.api_core import exceptions
from google.api_core.retry import Retry


_RETRYABLE = [
    exceptions.TooManyRequests,
    exceptions.InternalServerError,
    exceptions.BadGateway,
    exceptions.ServiceUnavailable,
    exceptions.DeadlineExceeded,
    exceptions.RetryError,
]


def is_retryable(exc):
    print(f"Checking exception for retryable: {type(exc).__name__}")
    return isinstance(exc, _RETRYABLE)


retry_policy = Retry(
    predicate=is_retryable, initial=60.0, maximum=600.0, multiplier=1.5, timeout=43200.0
)


def is_vulnerable_jupyter(ip, port, project, is_server=False):
    print("Checking Jupyter deployment...")
    ua = UserAgent()
    user_agent = ua.random
    print(f"HTTP GET request to: {ip}:{port}")
    try:
        resp = requests.get(f"http://{ip}:{port}", headers={"User-Agent": user_agent})
    except requests.exceptions.ConnectTimeout:
        print("Connection timeout.")
        return False
    if is_server and resp.status_code == 403:
        print(
            "Access to Jupyter Notebook Server is Forbidden "
            f"(403): [http://{ip}:{port}] in project [{project}]"
        )
        return False

    try:
        resp.raise_for_status()
    except Exception:
        print(
            f"Could not access address ({resp.status_code}): "
            f"[http://{ip}:{port}] in project [{project}]"
        )
        return False

    if "Token authentication is enabled" in resp.text:
        print(
            "Token authentication is enabled: "
            f"[http://{ip}:{port}] in project [{project}]"
        )
        return False

    print(
        "Potentially vulnerable Jupyter instance detected: "
        f"[http://{ip}:{port}] in project [{project}]"
    )

    return True


def _get_host_metadata(project, ipaddr):
    if os.environ.get("ASSET_API_SERV_ACCT"):
        iam_client = iam.Client()
        creds = iam_client.get_credentials(
            target_acct=os.environ.get("ASSET_API_SERV_ACCT")
        )
        client = asset_v1.AssetServiceClient(credentials=creds)
    else:
        client = asset_v1.AssetServiceClient()
    for _asset in client.list_assets(
        request={
            "parent": f"projects/{project}",
            "content_type": "RESOURCE",
            "asset_types": ["compute.googleapis.com/Instance"],
            "page_size": 10,
        },
        timeout=300,
        retry=retry_policy,
    ):
        try:
            for networkInterface in _asset.resource.data.get("networkInterfaces"):
                for accessConfig in networkInterface.get("accessConfigs"):
                    if accessConfig.get("natIP") == ipaddr:
                        return _asset
        except Exception:
            continue
    return None


def _get_startup_log(project, instance_id, last_starttime):
    print(f"GCE last startup time: {last_starttime}")
    if os.environ.get("LOGGING_API_SERV_ACCT"):
        iam_client = iam.Client()
        creds = iam_client.get_credentials(
            target_acct=os.environ.get("LOGGING_API_SERV_ACCT")
        )
        client = gcp_logging.Client(project=project, credentials=creds, _use_grpc=False)
    else:
        client = gcp_logging.Client(project=project, _use_grpc=False)
    start_ts = datetime.strptime(last_starttime, "%Y-%m-%dT%H:%M:%S.%f%z")
    window_start = start_ts - timedelta(minutes=30)
    window_start_str = window_start.astimezone(tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    window_end = start_ts + timedelta(minutes=30)
    window_end_str = window_end.astimezone(tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    for entry in client.list_entries(
        resource_names=f"projects/{project}",
        filter_=(
            'protoPayload.methodName:"compute.instances.start" '
            f'resource.labels.instance_id="{instance_id}" '
            "protoPayload.authorizationInfo.granted=true "
            f'timestamp>"{window_start_str}" '
            f'timestamp<"{window_end_str}"'
        ),
    ):
        return entry
    return None


def alert_vulnerable_jupyter(project, host, port_id, is_server):
    print("Alerting on vulnerable jupyter...")
    host_metadata = _get_host_metadata(project, host["address"]["addr"])
    hostdata = ""
    if host_metadata:
        hostdata = (
            f"- *GCE Name*: `{host_metadata.name}`\n"
            f"- *GCE Description*: `{host_metadata.resource.data.get('description')}`\n"
        )
        log_entry = _get_startup_log(
            project,
            host_metadata.resource.data.get("id"),
            host_metadata.resource.data.get("lastStartTimestamp"),
        )
        if log_entry and "authenticationInfo" in log_entry.payload:
            supplemental = (
                "- *Last Booted By*: "
                f"`{log_entry.payload.get('authenticationInfo').get('principalEmail')}`"
            )
            if "callerIp" in log_entry.payload.get("requestMetadata"):
                supplemental += (
                    " from "
                    f"`{log_entry.payload.get('requestMetadata').get('callerIp')}`"
                )
            supplemental += "\n"
            hostdata += supplemental
        hostdata += (
            "- *GCE Last Started*: "
            f"`{host_metadata.resource.data.get('lastStartTimestamp')}`\n"
            "- *GCE Created*: "
            f"`{host_metadata.resource.data.get('creationTimestamp')}`\n"
            "- *GCE Machine Type*: "
            f"`{host_metadata.resource.data.get('machineType')}`\n"
        )
    requests.post(
        os.environ("SLACK_ALERT_WEBHOOK"),
        json={
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": (
                            ":exclamation: Open Jupyter "
                            f"{'Server' if is_server else 'Notebook'} "
                            f"in GCP ({host['project']}) :exclamation:"
                        ),
                        "emoji": True,
                    },
                }
            ],
            "attachments": [
                {
                    "color": "#ff0000",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"- *URL*: http://{host['address']['addr']}"
                                    f":{port_id}/\n"
                                    f"- *Project*: `{host['project']}`\n"
                                    f"- *Network*:  `{host['network']}`\n"
                                    f"{hostdata}"
                                ),
                            },
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "emoji": True,
                                        "text": "Create Story",
                                    },
                                    "style": "primary",
                                    "action_id": "create_story",
                                    "value": "create_story",
                                },
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "emoji": True,
                                        "text": "Ignore",
                                    },
                                    "style": "danger",
                                    "action_id": "ignore_alert",
                                    "value": "ignore_alert",
                                    "confirm": {
                                        "title": {
                                            "type": "plain_text",
                                            "text": "Are you sure?",
                                        },
                                        "text": {
                                            "type": "mrkdwn",
                                            "text": "Your account will be registered.",
                                        },
                                        "confirm": {
                                            "type": "plain_text",
                                            "text": "Yes",
                                        },
                                        "deny": {
                                            "type": "plain_text",
                                            "text": "No",
                                        },
                                    },
                                },
                            ],
                        },
                    ],
                }
            ],
        },
    )
    return


def evaluate_results(message):
    message.ack()
    results_json = json.loads(message.data.decode("utf-8"))
    project = results_json["network"].split("/")[-4]
    host_list = results_json.get("host", [])
    if not isinstance(host_list, list):
        host_list = [host_list]

    for host in host_list:
        print(f"Checking: {results_json['network']} // {host['address']['addr']}")

        if "ports" not in host:
            continue

        port_list = host["ports"].get("port", [])
        if not isinstance(port_list, list):
            port_list = [port_list]

        for port in port_list:
            print(f"Port data: {port}")
            if isinstance(port, str):
                continue
            print(
                f"port: [{port.get('portid')}/{port.get('protocol')}"
                f"/{port['state'].get('state')}]"
            )

            scripts = port.get("script")
            if not scripts:
                print(f"No script in port {port['portid']}.")
                return

            if isinstance(scripts, dict):
                scripts = [scripts]

            for script in scripts:
                output = script.get("output")
                if output and "jupyter" in output.lower():
                    is_server = "server" in output.lower()
                    if is_vulnerable_jupyter(
                        host["address"]["addr"],
                        port["portid"],
                        project,
                        is_server,
                    ):
                        alert_vulnerable_jupyter(
                            project, host, port["portid"], is_server
                        )
                else:
                    print(f"Skipping checks with script output: {output}")
    print("Check complete.")


def main(config):
    subscription_project = config["subscription-project"]
    subscription_topic = config["subscription-topic"]
    if not os.environ.get("SLACK_ALERT_WEBHOOK"):
        os.environ["SLACK_ALERT_WEBHOOK"] = config["slack-alert-webhook"]
    if not os.environ.get("ASSET_API_SERV_ACCT"):
        os.environ["ASSET_API_SERV_ACCT"] = config["asset-api-serv-acct"]
    if not os.environ.get("LOGGING_API_SERV_ACCT"):
        os.environ["LOGGING_API_SERV_ACCT"] = config["logging-api-serv-acct"]

    subscriber = pubsub_v1.SubscriberClient()
    sub_path = subscriber.subscription_path(subscription_project, subscription_topic)
    set_ready(True)
    streaming_pull_future = subscriber.subscribe(sub_path, callback=evaluate_results)
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
        "--slack-alert-webhook",
        type=str,
        help=(),
        required=False,
    )
    parser.add_argument(
        "--asset-api-serv-acct",
        type=str,
        help=(
            "Optional: The service account email address to impersonate for "
            "Asset API calls. "
            "May also be provided in the ASSET_API_SERV_ACCT environment variable. "
        ),
        required=False,
    )
    parser.add_argument(
        "--logging-api-serv-acct",
        type=str,
        help=(
            "Optional: The service account email address to impersonate for "
            "Logging API calls. "
            "May also be provided in the LOGGING_API_SERV_ACCT environment variable. "
        ),
        required=False,
    )

    args = parser.parse_args()

    config = {
        "subscription-project": args.subscription_project
        or os.environ.get("SUBSCRIPTION_PROJECT"),
        "subscription-topic": args.subscription_topic
        or os.environ.get("SUBSCRIPTION_TOPIC"),
        "slack-alert-webhook": args.slack_alert_webhook
        or os.environ.get("SLACK_ALERT_WEBHOOK"),
        "asset-api-serv-acct": args.asset_api_serv_acct
        or os.environ.get("ASSET_API_SERV_ACCT"),
        "logging-api-serv-acct": args.asset_api_serv_acct
        or os.environ.get("LOGGING_API_SERV_ACCT"),
    }

    if (
        not config["subscription-project"]
        or not config["subscription-topic"]
        or not config["slack-alert-webhook"]
    ):
        print("ERROR: Missing required arguments.")
        print(
            "Please provide --subscription-project, --subscription-topic,"
            " and --slack-alert-webhook CLI arguments or set the "
            "SUBSCRIPTION_PROJECT, SUBSCRIPTION_TOPIC, and SLACK_ALERT_WEBHOOK "
            "environment variables.",
        )
        parser.print_help()
        sys.exit(1)

    return config


if __name__ == "__main__":
    # Start the health server in the background
    threading.Thread(target=run_health_server, daemon=True).start()
    config = get_config()
    main(config)
