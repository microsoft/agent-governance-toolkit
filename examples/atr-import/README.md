# ATR category import

This community example compiles Agent Threat Rules into one native ACS
manifest and Rego bundle per category.

## Usage

```bash
python examples/atr-import/import_atr.py rules/ \
  --out build/atr-policies \
  --manifest build/atr-summary.json
```

Optional filters include repeated `--category`, `--min-severity`, and
`--id-prefix`. `--watch` recompiles when source files change.

Each generated YAML file is an ACS manifest. Its sibling bundle directory
contains the Rego implementation.

## Test

```bash
pytest examples/atr-import/test_import_atr.py -v
```
