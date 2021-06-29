# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

RUN yum install -y tpm2-tss

COPY out/tagent /usr/bin/tagent
COPY dist/docker/entrypoint.sh /

RUN mkdir -p /opt/trustagent/var/system-info/
RUN mkdir /opt/trustagent/var/ramfs
RUN mkdir /var/log/trustagent /config/

RUN touch /.container-env
RUN chmod +x /entrypoint.sh

#Copy upgrade scripts
COPY out/upgrades/container_upgrade.sh /container_upgrade.sh
COPY out/upgrades/config_upgrade.sh /config_upgrade.sh
COPY upgrades/config/* /config/

RUN chmod -R +x /container_upgrade.sh /config_upgrade.sh /config

CMD ["/entrypoint.sh"]
