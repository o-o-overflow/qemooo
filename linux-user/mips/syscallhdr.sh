#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -x

in="$1"
out="$2"
my_abis=`echo "($3)" | tr ',' '|'`
prefix="$4"
offset="$5"

fileguard=LINUX_USER_MIPS_`basename "$out" | sed \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' \
    -e 's/[^A-Z0-9_]/_/g' -e 's/__/_/g'`
grep -E "^[0-9A-Fa-fXx]+[[:space:]]+${my_abis}" "$in" | sort -n | (
    printf "#ifndef %s\n" "${fileguard}"
    printf "#define %s\n" "${fileguard}"
    printf "\n"

    nxt=0
    while read nr abi name entry compat ; do
        if [ "$name" = "fadvise64" ] ; then
            name="fadvise64_64"
        fi
        if [ -z "$offset" ]; then
            printf "#define TARGET_NR_%s%s\t%s\n" \
                "${prefix}" "${name}" "${nr}"
        else
            printf "#define TARGET_NR_%s%s\t(%s + %s)\n" \
                "${prefix}" "${name}" "${offset}" "${nr}"
        fi
        nxt=$((nr+1))
    done


) > "$out"


offset=""
my_abis="(common)"
grep -E "^[0-9A-Fa-fXx]+[[:space:]]+${my_abis}" "$(dirname "$in")/arm_$(basename "$in")" | sort -n | (
    while read nr abi name entry ; do
    if [ -z "$offset" ]; then
        echo "#define ARM_TARGET_NR_${prefix}${name} $nr"
    else
        echo "#define ARM_TARGET_NR_${prefix}${name} ($offset + $nr)"
        fi
    done
) >> "$out"

cat "$(dirname "$in")/riscv32_syscall32_nr.header">> "$out"

(printf "\n"
    printf "#endif /* %s */" "${fileguard}"
    printf "\n") >> "$out"