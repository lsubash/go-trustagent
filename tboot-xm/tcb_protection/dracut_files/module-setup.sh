#!/bin/bash

#called by dracut
check()
{
	return 0
}

install()
{
	#copying all binaries to /bin
	inst /bin/base64 "/bin/base64"
	inst /sbin/lsof "/bin/lsof"
	inst /sbin/fuser "/bin/fuser"
	inst /bin/cut "/bin/cut"
	inst /bin/awk "/bin/awk"
	inst /bin/date "/bin/date"
	inst /bin/chmod "/bin/chmod"
	inst /bin/bash "/bin/bash"
	inst /bin/grep "/bin/grep"
	inst /bin/vi "/bin/vi"
	inst /usr/bin/wc "/bin/wc"
	inst /usr/bin/expr "/bin/expr"
	inst /usr/bin/xmllint "/bin/xmllint"
	inst /usr/bin/xargs "/bin/xargs"
	inst /usr/bin/printf "/bin/printf"
	inst /usr/bin/basename "/bin/basename"
	inst /bin/find "/bin/find"
	inst /usr/bin/sha1sum "/bin/sha1sum"
	inst /usr/bin/sha256sum "/bin/sha256sum"
	inst /usr/bin/sort "/bin/sort"
	if [ -e /usr/sbin/insmod ]
	then	
		inst /usr/sbin/insmod "/bin/insmod"
	else
		inst /sbin/insmod "/bin/insmod"
	fi
	if [ -e /usr/sbin/findfs ]
	then
		inst /usr/sbin/findfs "/bin/findfs"
	else
		inst /sbin/findfs "/bin/findfs"
	fi
	inst "$moddir"/bin/measure "/bin/measure"
	inst "$moddir"/lib/libwml.so "/lib/libwml.so"
	inst "$moddir"/bin/tpmextend "/bin/tpmextend"

	#installing the hook
	inst_hook pre-mount 70 "$moddir"/measure_host.sh
}
