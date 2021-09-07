#!/bin/bash

SERVICE_NAME=tagent
COMPONENT_NAME=trustagent
echo "Starting $COMPONENT_NAME config upgrade to v4.1.0"

echo "Downloading API token from AAS"
./$SERVICE_NAME setup download-api-token

echo "Completed $COMPONENT_NAME config upgrade to v4.1.0"
