Warning: This code is an alpha release. Please validate the results!

This script will parse all records in an SQLite Main Database File and WAL file. The files are processed at a physical level to ensure all data is extracted.

How it works:

1. [Main Database] - Identifies tables from the sqlite_master table
2. [Main Database] - Extracts all records from each table (including overflow data)
3. [WAL File] - Parses WAL frames and extracts all records from b-tree table leaf pages (currently does not include overflow data)
4. [WAL File] - Identifies the b-tree (table) the table leaf pages belongs to by walking backwards through the WAL file to find the parent interior page until a root page is identified.
5. Extracted Records are written to a csv file

Usage: 

-i Path to Main Database File 
-w Path to WAL File (optional)
-o Path to output csv including file name

Example usage: python SQBite.py -i Evidence\Photos.sqlite -w Evidence\Photos.sqlite-wal -o PhotosDatabaseExtraction.csv

Not Currently Supported: 

- Parsing Freelist Pages
- Parsing of Index B-trees (WITHOUT ROWID Tables are skipped as they use Index B-trees)
- Parsing of Pointer Map Pages
- Recovering Records from Freeblocks and Page Unallocated Space

Known Issues:

- Overflow Records in the WAL are not completely reconstructed
