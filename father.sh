#!/bin/sh
echo "$0: parent script pid: $$"
echo "$0: before my son"
./son.sh
echo "$0: after my son"
touch /tmp/$$
