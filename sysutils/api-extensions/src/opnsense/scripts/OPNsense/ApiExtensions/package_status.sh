#!/bin/sh
set -eu

PACKAGE=${1:-}
case "${PACKAGE}" in
    [A-Za-z0-9]*) ;;
    *)
        printf '%s\n' 'invalid-package-name'
        exit 64
        ;;
esac
case "${PACKAGE}" in
    *[!A-Za-z0-9._+-]*)
        printf '%s\n' 'invalid-package-name'
        exit 64
        ;;
esac

PKG=/usr/local/sbin/pkg
GREP=/usr/bin/grep
PROVIDED=0
if "${PKG}" rquery -U '%n' "${PACKAGE}" 2>/dev/null | "${GREP}" -Fqx "${PACKAGE}"; then
    PROVIDED=1
fi

if ! "${PKG}" info -e "${PACKAGE}" >/dev/null 2>&1; then
    printf 'not-installed|||%s\n' "${PROVIDED}"
    exit 0
fi

LOCAL_STATE=$("${PKG}" query '%n|||%v|||%k|||%R|||%o' "${PACKAGE}")
printf '%s|||%s\n' "${LOCAL_STATE}" "${PROVIDED}"
