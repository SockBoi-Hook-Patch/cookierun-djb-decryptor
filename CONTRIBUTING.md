# Contributing

1. Create a focused branch for each change.
2. Add unit tests for parsing, malformed input, and boundary conditions.
3. Do not commit proprietary .djb or decrypted .bin files. Use synthetic fixtures or document local-only sample hashes and expected outcomes.
4. Run python -m py_compile src/cookierun_djb/*.py and pytest -q.
5. Label format assumptions explicitly; do not claim game-loader compatibility without genuine Gen1 and Gen2 evidence.

Before contributing key material or copied code, document its provenance and license compatibility in NOTICE.md.
