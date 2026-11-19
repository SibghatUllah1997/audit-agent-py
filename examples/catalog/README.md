# v0.2.0 rule examples (A021–A027)

`flagged/` holds one Solidity file per rule that sibaudit reports. `fixed/` holds the cleaned version of the same contract.

```bash
python3 -m sibaudit examples/catalog/flagged
python3 -m sibaudit examples/catalog/fixed
```

The second command should print nothing and exit 0. The sources match `sibaudit --explain CODE` and the catalog in `docs/catalog-v0.2.md`.
