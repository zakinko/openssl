#!/bin/sh
# Boot NetBSD/i386 from zakinko/netbsd-ci-images under KVM and run
# Configure there: once on the tree before the hw.model fix, which is
# expected to stop, and once on the fixed tree, which is then built and
# tested.  vmactions has no NetBSD/i386 image.
#
#   sh netbsd-i386.sh <before-rev> <after-rev>

set -e

BEFORE=$1
AFTER=$2
NAME=${NAME:-i386-11.0}
PORT=2222
WORK=$PWD/.vm
IMG=https://github.com/zakinko/netbsd-ci-images/releases/download/images
RAW=https://raw.githubusercontent.com/zakinko/netbsd-ci-images/main

mkdir -p "$WORK"
git archive --format=tar --prefix=before/ "$BEFORE" > "$WORK/before.tar"
git archive --format=tar --prefix=after/ "$AFTER" > "$WORK/after.tar"
cd "$WORK"
for f in runvm.sh stopvm.sh; do curl -fsSL -o "$f" "$RAW/$f"; done
for f in $NAME.qcow2 $NAME.qemu; do curl -fsSL -o "$f" "$IMG/$f"; done

cleanup() {
	rc=$?
	DIR=. sh stopvm.sh "$NAME" > /dev/null 2>&1 || true
	exit $rc
}
DIR=. sh runvm.sh "$NAME" "$PORT"
trap cleanup EXIT INT TERM
SSH=$(cat "$WORK/$NAME.ssh")

# The runner has no IPv6 route, and qemu's user-mode NAT hands the guest
# one; pkg_add would wait on every AAAA first.
$SSH sh -s <<'GUEST'
set -e
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/bin
printf '\nnoipv6\nnoipv6rs\n' >> /etc/dhcpcd.conf
sysctl -w net.inet6.ip6.accept_rtadv=0 > /dev/null 2>&1 || true
route -qn add -inet6 2000::/3 ::1 -reject > /dev/null 2>&1 || true
route -qn delete -inet6 default > /dev/null 2>&1 || true
uname -a
sysctl -n hw.model | od -c | tail -3
PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/i386/$(uname -r | cut -d_ -f1)/All
export PKG_PATH
pkg_add perl
perl -v | sed -n 2p
GUEST

$SSH "cd /root && tar xf -" < before.tar
$SSH "cd /root && tar xf -" < after.tar

echo "=== before the fix ==="
$SSH "cd /root/before && PATH=\$PATH:/usr/pkg/bin ./Configure 2>&1 | tail -8" || true

echo "=== after the fix ==="
$SSH sh -s <<'GUEST'
set -e
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/pkg/bin
cd /root/after
./Configure | grep -i target
make -j$(sysctl -n hw.ncpu) > build.log 2>&1 || { tail -40 build.log; exit 1; }
echo "build ok, warnings: $(grep -c 'warning:' build.log)"
grep 'warning:' build.log | sort -u | head -20
make test TESTS='test_internal_bn test_ec test_rsa test_evp' HARNESS_JOBS=4 2>&1 | tail -15
GUEST
