#!/usr/bin/python3
# Copyright 2023 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

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
