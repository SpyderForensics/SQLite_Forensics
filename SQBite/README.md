Warning: This code is an beta release. Please validate the results!

This script will parse all records in an SQLite Main Database File and WAL file. The files are processed at a physical level to ensure all data is extracted.

Features

1. [Main Database] - Extracts all allocated records (including overflow data), freeblocks, page unallocated space from table leaf pages
2. [Main Database] - Extracts all page unallocated space from table interior, index interior and index leaf pages
3. [Main Database] - Identifies Freelist Trunk Pages and parses freelist page array and page unallocated space
4. [Main Database] - Extracts all allocated records,, freeblocks, page unallocated space from Freelist Table Leaf pages
5. [Main Database] - Extracts all page unallocated space from all other freelist pages
6. [WAL File] - Parses all WAL frames 
7. [WAL File] - Extracts all allocated records (currently does not include overflow data), freeblocks, page unallocated space from table leaf pages
8. [WAL File] - Extracts all page unallocated space from table interior, index interior and index leaf pagese
9. [WAL File] - Identifies the b-tree (table) the table leaf pages belongs to by walking backwards through the WAL file to find the parent interior page until a root page is identified.
10. [Output] - Rebuilds the original database (except sqlite internal tables)
11. [Output] - Inserts all extracted records into the appropriate table
12. [Output] - Freelist Pages are added to a Freelist Table
13. [Output] - Unallocated Space and Freeblocks are added to Recovered_Records Table
14. [Output] - An unknown table is created to store records where there is a schema mismatch with the table assignment (from wal file)
15. [Record Classification (Experiremental)] - Identifies the Active record
16. [Record Classification (Experiremental)] - Identifies Duplicate versions of the Active record
18. [Record Classification (Experiremental)] - Identifies Old records that have been deleted in the WAL but a checkpoint has not been performed
19. [Record Classification (Experiremental)] - Compares Records based on rowid to identifiy modified records or records where the rowid has been reused.
20. [InstaSearch (Experimental)] - Performs a keyword search across all tables in the database and outputs the Record_ID and column name and column content that had the hit

Usage: 

-i Path to Main Database File 
-w Path to WAL File (optional)
-o Path to output folder
-c Record Classification (optional)
-s Keyword to Search

Example usage: python SQBite.py -i Evidence\Photos.sqlite -w Evidence\Photos.sqlite-wal -o PhotosDatabaseExtraction -c -s Spyder

Not Currently Supported: 

- Parsing of Index B-trees (WITHOUT ROWID Tables are skipped as they use Index B-trees)
- Parsing of Pointer Map Pages
- Freelist Page Identification in the WAL

Known Issues:

- Overflow Records in the WAL are not completely reconstructed

Beta 2 Bug Fixes:

- Records with overflow in Main Database File are now correctly parsed
- The column types are now extracted from the original database and are applied when writing the output SQLite Database

Beta 3 Changes:

- Beta 2 overflow record code worked in some scenarioes but no other. The new version has a temporary fix so overflow records in Main Database File are now correctly parsed
- Fixed an issue when the column type was not declared in the original database
- If there is an error creating a table in the output the table and sql language is printed to the console (i.e Virtual Tables)
- Additional Print Statements and some other visual changes
- InstaSearch now searches BLOB fields
- InstaSearch now ignores columns created by SQBite in the output database
- Small Changes to the InstaSearch output text file to make it easier to read
