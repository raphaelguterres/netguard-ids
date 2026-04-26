"""CLI entrypoint for `python -m netguard_agent`."""

from .service import main

raise SystemExit(main())
