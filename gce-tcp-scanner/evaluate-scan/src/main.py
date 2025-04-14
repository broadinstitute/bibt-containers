
def evaluate_results(results_json):
    host_list = results_json.get("host", [])
    if not isinstance(host_list, list):
        host_list = [host_list]

    for host in host_list:
        print(
            f"Checking: {host['project']} // {host['network']} "
            f"// {host['address']['addr']}"
        )

        if "ports" not in host:
            continue

        for port in host["ports"].get("port", []):
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
