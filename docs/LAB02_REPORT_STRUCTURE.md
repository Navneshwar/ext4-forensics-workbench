# Lab #02 report structure in v0.4

The generated report follows the lab's requested six beats:

1. Mandate
2. Integrity
3. Method
4. Findings
5. Limits
6. Conclusion

It also explicitly answers the eight deliverables:

1. image SHA-256
2. filesystem + volume label
3. deleted files + inode numbers
4. USB connection time
5. archive creation time
6. confidential document + recovery method
7. metadata recovery vs carving
8. facts vs hypotheses

The application adds live-artifact inventory, timeline rows, recovered-content strings, and recovered-ZIP member analysis so the report can show supporting evidence rather than just the final answer.

## v0.4 implementation note

The artifact extractor uses pytsk3's root-directory traversal and reads file contents directly from each directory entry. This avoids the path-reopen failure mode that caused empty artifact sections in the earlier report.
