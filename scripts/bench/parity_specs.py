#!/usr/bin/env python3
"""The parity class registry (j1mk.1): one entry per reference-parity class bead.

The harness (parity_run.py) owns the mechanism; each class bead (j1mk.13 hidden parameters,
j1mk.14 CORS, j1mk.15 CRLF, ...) owns ONE entry here — the seed targets both sides see, the
scanner rows the comparison counts, the reference tool's argv, and the ground truth when the
target declares it. Keeping the specs in one reviewed file is what makes "same targets, same
endpoints, compare what each finds" auditable across classes.

The spec shape is documented in parity_run.py's module docstring.
"""

CLASSES = {}
