# -*- coding: utf-8 -*-
# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import datetime
import logging
import os
import os.path

AV_DEFINITION_S3_BUCKET = os.getenv("AV_DEFINITION_S3_BUCKET")
AV_DEFINITION_S3_PREFIX = os.getenv("AV_DEFINITION_S3_PREFIX", "clamav_defs")
AV_DEFINITION_PATH = os.getenv("AV_DEFINITION_PATH", "/tmp/clamav_defs")
AV_SCAN_START_SNS_ARN = os.getenv("AV_SCAN_START_SNS_ARN")
AV_SCAN_START_METADATA = os.getenv("AV_SCAN_START_METADATA", "av-scan-start")
AV_SIGNATURE_METADATA = os.getenv("AV_SIGNATURE_METADATA", "av-signature")
AV_SIGNATURE_OK = "OK"
AV_SIGNATURE_UNKNOWN = "UNKNOWN"
AV_STATUS_CLEAN = os.getenv("AV_STATUS_CLEAN", "CLEAN")
AV_STATUS_INFECTED = os.getenv("AV_STATUS_INFECTED", "INFECTED")
AV_STATUS_METADATA = os.getenv("AV_STATUS_METADATA", "av-status")
AV_STATUS_SNS_ARN = os.getenv("AV_STATUS_SNS_ARN")
AV_STATUS_SNS_PUBLISH_CLEAN = os.getenv("AV_STATUS_SNS_PUBLISH_CLEAN", "True")
AV_STATUS_SNS_PUBLISH_INFECTED = os.getenv("AV_STATUS_SNS_PUBLISH_INFECTED", "True")
AV_TIMESTAMP_METADATA = os.getenv("AV_TIMESTAMP_METADATA", "av-timestamp")
CLAMAVLIB_PATH = os.getenv("CLAMAVLIB_PATH", "")
CLAMSCAN_PATH = os.getenv("CLAMSCAN_PATH", "/usr/bin/clamscan")
FRESHCLAM_PATH = os.getenv("FRESHCLAM_PATH", "/usr/bin/freshclam")
AV_PROCESS_ORIGINAL_VERSION_ONLY = os.getenv(
    "AV_PROCESS_ORIGINAL_VERSION_ONLY", "False"
)
AV_DELETE_INFECTED_FILES = os.getenv("AV_DELETE_INFECTED_FILES", "False")

AV_DEFINITION_FILE_PREFIXES = ["main", "daily", "bytecode"]
AV_DEFINITION_FILE_SUFFIXES = ["cld", "cvd"]

log = logging.getLogger(__name__)


def create_dir(path):
    if not os.path.exists(path):
        try:
            log.debug("Attempting to create directory %s.\n", path)
            os.makedirs(path)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise


def get_timestamp():
    return datetime.datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")


def setup_logging():
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    if len(logging.getLogger().handlers) > 0:
        # The Lambda environment pre-configures a handler logging to stderr.
        # If a handler is already configured,
        # `.basicConfig` does not execute. Thus we set the level directly.
        logging.getLogger().setLevel(level)
    else:
        logging.basicConfig(level=level)
    # quiet noisy modules
    for module in ["boto3", "botocore", "urllib3"]:
        logging.getLogger(module).setLevel("WARNING")
