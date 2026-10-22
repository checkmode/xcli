#!/usr/bin/env python3
"""Install a legacy application fixture using the currently available core pin."""
from pathlib import Path
import runpy
import sys


if __name__ == '__main__':
    current = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'provision.py'))
    source = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(source / 'deploy'))
    import provision
    # The adoption fixture predates immutable releases and pins a withdrawn core.
    # Preserve its application and installer while replacing only this dependency.
    provision.XRAY_VERSION = current['XRAY_VERSION']
    provision.XRAY_ASSETS = current['XRAY_ASSETS']
    import install
    raise SystemExit(install.main(sys.argv[2:]))
