#!/usr/bin/python3
import asyncio
import json
import os
import subprocess
import sys
import traceback
import time

from azure.iot.device.aio import IoTHubModuleClient


async def main():
    try:
        out = subprocess.run(
            args=["/usr/bin/nt-connect", "bootstrap"], capture_output=True, check=True
        )
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr.decode())
        raise
    identity = json.loads(out.stdout.decode())
    try:
        client = IoTHubModuleClient.create_from_edge_environment()
    except:
        return

    await client.patch_twin_reported_properties(identity)
    sleep_time = 1.0
    for _ in range(10):
        twin = await client.get_twin()
        if "pubkey" in twin["reported"]:
            break
        time.sleep(sleep_time)
        sleep_time *= 2


if __name__ == "__main__":
    asyncio.run(main())
    os.execv("/usr/bin/nt-connect", ["nt-connect"] + sys.argv[1:])
