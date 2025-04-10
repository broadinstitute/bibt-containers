#!/usr/bin/env python3
import argparse
import re
import sys
import os
from copy import deepcopy
from random import shuffle
from time import sleep
import tempfile
from datetime import date

from bibt.gcp import iam
from bibt.gcp import storage
from google.api_core import exceptions
from google.api_core.retry import Retry
from google.cloud import asset_v1
from bibt.gcp import pubsub

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


def get_resources(type, org_id, asset_api_serv_acct=None):
    """For the given organization, pulls all resources of the given type."""
    if asset_api_serv_acct:
        iam_client = iam.Client()
        creds = iam_client.get_credentials(target_acct=asset_api_serv_acct)
        client = asset_v1.AssetServiceClient(credentials=creds)
    else:
        client = asset_v1.AssetServiceClient()
    pagesize = 250
    response = client.list_assets(
        request={
            # "parent": f"projects/bits-bt-aim-prod",
            "parent": f"organizations/{org_id}",
            "asset_types": [f"compute.googleapis.com/{type}"],
            "content_type": "RESOURCE",
            "page_size": pagesize,
        },
        timeout=300.0,
        retry=retry_policy,
    )

    resources = []
    c = 1
    for resource in response:
        resources.append(resource)
        c += 1
        if c % (pagesize * 90) == 0:
            sleep(61)
        # firewalls.append(json.loads(resource.__class__.to_json(resource)))
        # gce_ips.extend(resource.additional_attributes.get("externalIPs", []))

    return resources


def get_instance_network_configs(instances):
    """Takes a list of GCE instances and returns a dictionary of networks and
    lists of NAT IPs that belong to them.

    The output looks like:
    {
        "projects/123456789/networks/default": [ # pragma: allowlist secret
            "1.2.3.4",
            "4.3.2.1"
        ]
    }
    """
    network_configs = {}
    for instance in instances:
        for ni in instance.resource.data["networkInterfaces"]:
            if "accessConfigs" not in ni:
                continue
            for ac in ni["accessConfigs"]:
                if "natIP" in ac:
                    if ni["network"] in network_configs:
                        network_configs[ni["network"]].append(ac["natIP"])
                    else:
                        network_configs[ni["network"]] = [ac["natIP"]]
    return network_configs


def merge_ports(ports_list, port):
    """Takes a list of ports and port ranges and a new port or port range
    and merges it with the list.

    The output looks like:
    ["1-444", "447", "450-65535"]
    """
    merged_ports = []
    if "-" in port:
        p1, p2 = port.split("-")
        p_low = min(int(p1), int(p2))
        p_high = max(int(p1), int(p2))
        added_range = False
        for _p in ports_list:
            if "-" in _p:  # we're comparing 2 ranges
                _p1, _p2 = _p.split("-")
                _p_low = min(int(_p1), int(_p2))
                _p_high = max(int(_p1), int(_p2))
                # no overlap
                #  p        |-------|
                # _p   |--|
                if int(p_low) > int(_p_high) or int(p_high) < int(_p_low):
                    merged_ports.append(_p)
                # overlap pattern 1    overlap pattern 2
                #  p       |-----|      p       |--|
                # _p    |-----|        _p     |-----|
                elif int(p_low) >= int(_p_low) and int(p_low) <= int(_p_high):
                    if int(p_high) <= int(_p_high):
                        # print(f"port range ({port}) is contained within
                        # existing range ({_p}). returning.")
                        return sorted(deepcopy(ports_list))  # p2
                    else:
                        merged_ports.append(f"{_p_low}-{p_high}")  # p1
                        added_range = True
                # overlap pattern 3    overlap pattern 4
                #  p   |-----|          p    |-----|
                # _p      |-----|      _p     |---|
                elif int(_p_low) >= int(p_low) and int(_p_low) <= int(p_high):
                    if int(_p_high) >= int(p_high):
                        merged_ports.append(f"{p_low}-{_p_high}")  # p3
                        added_range = True
            else:  # we're comparing a range with a port
                if not (int(_p) >= int(p_low) and int(_p) <= int(p_high)):
                    merged_ports.append(_p)

        if not added_range:
            # print(f"adding port ({port}) to list.")
            merged_ports.append(port)

    else:
        for _p in ports_list:
            if "-" in _p:  # we're comparing a port with a range
                _p1, _p2 = _p.split("-")
                _p_low = min(int(_p1), int(_p2))
                _p_high = max(int(_p1), int(_p2))
                if int(port) >= int(_p_low) and int(port) <= int(_p_high):
                    # print(f"port ({port}) is in the range ({_p}), returning")
                    return sorted(deepcopy(ports_list))
                merged_ports.append(_p)
            else:
                if int(_p) == int(port):  # we're comparing 2 ports
                    # print(f"port ({port}) already present, returning.")
                    return sorted(deepcopy(ports_list))
                merged_ports.append(_p)
        # print(f"adding port ({port}) to list.")
        merged_ports.append(port)

    return sorted(merged_ports)


def get_open_networks(firewalls):
    """Iterates through all firewalls in a GCP organization and returns
    a dictionary of those which permit (non-ICMP) ingress traffic from 0.0.0.0/0.

    The output looks like:
    {
        "projects/123456789/global/networks/default": ["1-65535"], # pragma: allowlist secret
        "projects/123456789/global/networks/other": ["1-129", "8888"],
        ...
    }
    """  # noqa
    network_configs = {}
    for firewall in firewalls:
        if firewall.resource.data.get("disabled", False):
            continue
        if firewall.resource.data["direction"] == "EGRESS":
            continue
        if "allowed" not in firewall.resource.data:
            continue
        if "sourceRanges" not in firewall.resource.data:
            continue
        if "0.0.0.0/0" not in firewall.resource.data["sourceRanges"]:
            continue

        network = firewall.resource.data["network"]
        if network not in network_configs:
            network_configs[network] = []
        for a in firewall.resource.data["allowed"]:
            if a["IPProtocol"] == "icmp":
                continue
            if "ports" not in a and re.match(r"^[-,a-zA-Z]+$", a["IPProtocol"]):
                print(
                    f"WARNING: fully open network found: {network},{firewall.name},"
                    f'{firewall.resource.data["id"]},'
                    f'{firewall.resource.data.get("targetTags")},{dict(a)}'
                )
                network_configs[network] = ["1-65535"]
                break
            elif "ports" in a:
                for port in a["ports"]:
                    network_configs[network] = merge_ports(
                        network_configs[network], str(port)
                    )
            else:
                for port in a["IPProtocol"].split(","):
                    network_configs[network] = merge_ports(
                        network_configs[network], port
                    )
    return network_configs


def main(config):
    bucket = config["gcs-bucket"]
    org_id = config["gcp-org-id"]
    pubsub_topic_uri = config["pubsub-topic-uri"]
    asset_api_serv_acct = config["asset-api-serv-acct"]

    print("Getting all firewalls...")
    # Format:
    # open_networks_dict = {
    #     "projects/123456789/global/networks/default": ["1-122","49","8000-9000"],  # pragma: allowlist secret # noqa
    #     "projects/987654321/global/networks/default": ["1-65535"],  # pragma: allowlist secret # noqa
    # }
    firewalls = get_resources("Firewall", org_id, asset_api_serv_acct)
    open_networks_dict = get_open_networks(firewalls)

    print("Getting all GCE instances...")
    # Format:
    # network_gces_dict = {
    #     "projects/123456789/networks/default": ["1.2.3.4","4.4.4.4"],  # pragma: allowlist secret # noqa
    #     "projects/987654321/global/networks/default": ["4.3.2.1", "1.1.1.1"],  # pragma: allowlist secret # noqa
    # }
    instances = get_resources("Instance", org_id, asset_api_serv_acct)
    network_gces_dict = get_instance_network_configs(instances)

    print("Formatting for and shuffling list for randomness while scanning...")
    # Formatting:
    # network_gce_list = [
    #   {"projects/123456789/global/networks/default": ["1.2.3.4", "4.4.4.4"]},  # pragma: allowlist secret # noqa
    #   {"projects/987654321/global/networks/default": ["4.3.2.1", "1.1.1.1"]},  # pragma: allowlist secret # noqa
    # ]
    network_gce_list = []
    for k in network_gces_dict.keys():
        network_gce_list.append({k: network_gces_dict[k]})
    shuffle(network_gce_list)

    if pubsub_topic_uri:
        print("Pushing scan data to nmap pubsub topic...")
        # iterating through each network with GCEs with NAT IPs, formatting data,
        # and sending to pubsub topic.
        # Format:
        # message = {
        #   "network": "projects/123456789/global/networks/default",  # pragma: allowlist secret # noqa
        #   "ips": ["1.2.3.4","4.4.4.4"],
        #   "ports": ["1-122","49","8000-9000"],
        # }
        for i in range(len(network_gce_list)):
            # .keys() returns a list so just grab first element since this is a
            # 1-key dictionary:
            network = list(network_gce_list[i].keys())[0]
            ports = open_networks_dict.get(network, None)
            if not ports:
                continue
            message = {
                "network": network,
                "ips": network_gce_list[i][network],
                "ports": ports,
            }
            pubsub_client = pubsub.Client()
            pubsub_client.send_pubsub(pubsub_topic_uri, payload=message)
            print(f"Sent message to pubsub topic: {message}")

    print("Preparing data for upload to GCS...")
    # The output looks like:
    # projects.123456789.global.networks.default|1.2.3.4,4.4.4.4|1-122,49,8000-9000
    # projects.987654321.global.networks.default|4.3.2.1,1.1.1.1|1-65535
    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, "w") as f:
        for i in range(len(network_gce_list)):
            n = list(network_gce_list[i].keys())[0]
            ports = open_networks_dict.get(n, None)
            if not ports:
                continue
            f.write(f'{n}|{" ".join(network_gce_list[i][n])}|{",".join(ports)}\n')

    storage_client = storage.Client()
    scan_config_blob = f"{date.today().isoformat()}/scan-config.txt"
    storage_client.write_gcs_from_file(
        bucket, scan_config_blob, tmp.name, mime_type="text/plain"
    )
    print(f"Scan config written to gs://{bucket}/{scan_config_blob}")


def get_config():
    parser = argparse.ArgumentParser(
        description=(
            "Generates a scan config based on GCE NAT IPs and open VPC Firewalls."
            "Configuration may be passed via CLI arguments or environment variables. "
            "Values passed via CLI will take precedence over environment variables."
        )
    )

    parser.add_argument(
        "--gcs-bucket",
        type=str,
        help=(
            "The GCP bucket to use. May also be provided in the GCS_BUCKET "
            "environment variable. "
        ),
        required=False,
    )
    parser.add_argument(
        "--gcp-org-id",
        type=str,
        help=(
            'Your GCP organization ID, e.g. "123456789". '
            "May also be provided in the GCP_ORG_ID environment variable. "
        ),
        required=False,
    )
    parser.add_argument(
        "--pubsub-topic-uri",
        type=str,
        help=(
            "Optional: The pubsub topic URI to which to send host discovery data. "
            "Note that it should be the full topic URI, e.g. "
            "`projects/123456789/topics/my-topic`. "
            "May also be provided in the PUBSUB_TOPIC_URI environment variable. "
        ),
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

    # for i in range(len(sys.argv)):
    #     print(f"{i}: {sys.argv[i]}")

    args = parser.parse_args()

    config = {
        "gcp-org-id": args.gcp_org_id or os.environ.get("GCP_ORG_ID"),
        "gcs-bucket": args.gcs_bucket or os.environ.get("GCS_BUCKET"),
        "pubsub_topic_uri": args.pubsub_topic_uri or os.environ.get("PUBSUB_TOPIC_URI"),
        "asset-api-serv-acct": args.asset_api_serv_acct
        or os.environ.get("ASSET_API_SERV_ACCT"),
    }

    if not config["gcs-bucket"] or not config["gcp-org-id"]:
        print("ERROR: Missing required arguments.")
        print(
            "Please provide --gcs-bucket and --gcp-org-id or set "
            "the GCS_BUCKET and GCP_ORG_ID environment variables."
        )
        parser.print_help()
        sys.exit(1)

    return config


if __name__ == "__main__":
    config = get_config()
    print(f"Using the following config: {config}")
    main(config)
