# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

COPY out/tagent /usr/bin/tagent
COPY dist/docker/entrypoint.sh /

RUN apt-get update -y && apt-get install -y libtss2-esys0 && \
    apt-get clean && apt-get autoclean && \
    mkdir -p /opt/trustagent/var/system-info/ /opt/trustagent/var/ramfs /var/log/trustagent /config/ && \
    touch /.container-env && \
    chmod +x /entrypoint.sh

#Copy upgrade scripts
COPY out/upgrades/container_upgrade.sh /container_upgrade.sh
COPY out/upgrades/config_upgrade.sh /config_upgrade.sh
COPY upgrades/config/* /config/

RUN chmod -R +x /container_upgrade.sh /config_upgrade.sh /config

CMD ["/entrypoint.sh"]
