# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

COPY out/tagent /usr/bin/tagent
COPY dist/docker/entrypoint.sh /

RUN yum install -y tpm2-tss && \
    rm -rf /var/cache /var/log/dnf* /var/log/yum.* && \
    mkdir -p /opt/trustagent/var/system-info/ /opt/trustagent/var/ramfs /var/log/trustagent /config/ && \
    touch /.container-env &&\
    chmod +x /entrypoint.sh

#Copy upgrade scripts
COPY out/upgrades/container_upgrade.sh /container_upgrade.sh
COPY out/upgrades/config_upgrade.sh /config_upgrade.sh
COPY upgrades/config/* /config/

RUN chmod -R +x /container_upgrade.sh /config_upgrade.sh /config

CMD ["/entrypoint.sh"]
