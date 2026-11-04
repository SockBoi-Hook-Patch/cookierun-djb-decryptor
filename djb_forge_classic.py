#!/usr/bin/env python3
import sys
from cookierun_djb.cli import main
if __name__ == '__main__':
    raise SystemExit(main(['forge', *sys.argv[1:]]))
