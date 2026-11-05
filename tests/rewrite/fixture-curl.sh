#!/bin/sh
# Supply a synthetic Git archive to the one-click installer in namespace tests.
case "$*" in
  *codeload.github.com/checkmode/xcli/tar.gz/*)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = -o ]; then cp "$XCLI_TEST_BOOTSTRAP_ARCHIVE" "$2"; exit; fi
      shift
    done
    exit 1 ;;
  *) exec /usr/bin/curl "$@" ;;
esac
