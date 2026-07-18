# shellcheck shell=sh
# C-compile image workload (issue #224 c-compile profile), run in the guest via
# `/bin/sh -c`: a small multi-file project built with make, then a larger single
# translation unit compiled with gcc -O1 (the readlinkat/execve-of-cc1/as/ld
# signature). Prints one sentinel token on success. POSIX sh (dash). gcc:14 is
# Debian-based, so this also proves the setuid/setgid unpack degrade on a
# shadow-suite image.
#
# The Makefile uses .RECIPEPREFIX so its recipes are prefixed with '>' rather
# than a literal tab, which keeps this heredoc robust. Scaled down from #224's
# 30-file project + 8 MB TU to keep CI minutes sane; the syscall signature
# (per-TU path resolution, compiler/assembler/linker exec) is preserved.
set -e

d=/tmp/cwork
rm -rf "$d"
mkdir -p "$d"
cd "$d"

cat > mathx.h <<'EOF'
#ifndef MATHX_H
#define MATHX_H
int tri(int n);
#endif
EOF
cat > mathx.c <<'EOF'
#include "mathx.h"
int tri(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i;
    return s;
}
EOF
cat > main.c <<'EOF'
#include <stdio.h>
#include "mathx.h"
int main(void) {
    printf("%d\n", tri(100));
    return 0;
}
EOF
cat > Makefile <<'EOF'
.RECIPEPREFIX = >
CC ?= gcc
app: main.o mathx.o
> $(CC) -O1 -o app main.o mathx.o
%.o: %.c mathx.h
> $(CC) -O1 -c -o $@ $<
EOF

make -j1
r=$(./app)
if [ "$r" != "5050" ]; then
    echo "make project produced: $r" >&2
    exit 1
fi

# A larger single TU: 1000 functions dispatched through a table, summed and
# checked. Exercises a heavier gcc -O1 compile+link than the tiny project above.
awk 'BEGIN {
    for (i = 0; i < 1000; i++) print "int f" i "(void){return " i ";}";
    printf "typedef int(*fn)(void);\nstatic fn t[]={";
    for (i = 0; i < 1000; i++) printf "f%d,", i;
    print "};";
    print "int main(void){long s=0;for(int i=0;i<1000;i++)s+=t[i]();return s==499500?0:1;}";
}' > big.c
gcc -O1 -o big big.c
./big

echo elfuse-oci-c-workload-ok
