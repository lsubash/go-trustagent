# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

RUN yum install -y tpm2-tss dmidecode redhat-lsb-core sudo

COPY dist/linux/module_analysis.sh /tmp/
COPY dist/linux/module_analysis_da.sh /tmp/
COPY dist/linux/module_analysis_da_tcg.sh /tmp/

COPY out/tagent /usr/bin/tagent
COPY dist/docker/entrypoint.sh /

RUN mkdir -p /opt/trustagent/var/system-info/
RUN mkdir /opt/trustagent/var/ramfs
RUN mkdir /var/log/trustagent

RUN touch /.container-env
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
