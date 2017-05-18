#!/bin/sh
echo "$0: hello world"
sleep 3
echo "$0: I am son (pid: $$)"
touch /tmp/$$
echo "$0: bye"
