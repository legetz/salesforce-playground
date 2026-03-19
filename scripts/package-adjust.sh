#!/bin/bash
#
# Author: Leo Jokinen (2026-02-04)
# - Rebuild package.xml out from the force-app folder
#
set -euo pipefail

sf project manifest generate --source-dir force-app/main/default --output-dir manifest --name package
