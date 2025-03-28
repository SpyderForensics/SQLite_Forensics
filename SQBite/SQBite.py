#This python script will extract records from an SQLite database and its associated WAL file.
#
#
#Copyright(C) 2025 Spyder Forensics LLC (www.spyderforensics.com)
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You can view the GNU General Public License at <https://www.gnu.org/licenses/>.
#
# Version History:
# v alpha 2025-01-09
# v beta 2025-03-28


import os
import argparse
import datetime
from Modules.parse_sqlite_file import parse_sqlite_file
from Modules.parse_wal_file import parse_wal_file
from Modules.output_sqlite import write_to_sqlite
from Modules.recordclassify import classify_records
from Modules.instasearch import insta_search

def _main(db_file, wal_file, output_folder, search_term):
    print(r"""
                                                    \_______/
  _____    ____    ____    _   _                `.,-'\_____/`-.,'
 / ____|  / __ \  |  _ \  (_) | |                /`..'\ _ /`.,'\  
| (___   | |  | | | |_) |  _  | |_    ___       /  /`.,' `.,'\  \       
 \___ \  | |  | | |  _ <  | | | __|  / _ \   __/__/__/     \__\__\__
 ____) | | |__| | | |_) | | | | |_  |  __/     \  \  \     /  /  /    
|_____/   \___\ \ |____/  |_|  \__|  \___|      \  \,'`._,'`./  /  
               \_\                               \,'`./___\,'`./
                                                ,'`-./_____\,-'`.
Chomping SQLite Databases One Page at a time        /       \

Version: Beta March, 2025
Author: Spyder Forensics Training
Website: www.spyderforensics.com

Warning: This is the Beta code please validate the results (You should always validate anyway)

Note: Table Assignments from the WAL file should be verified

Now Supported

- Parsing Freelist Pages
- Output SQLite Database
- Basic Record Recovery from Freeblocks and Page Unallocated Space (All Pages)
- Record Classification (Experimental)
- Insta Search (Experimental)

Not Currently Supported: 

- Parsing of Index B-trees (Including WITHOUT ROWID Tables as they use Index B-trees)
- Parsing of Pointer Map Pages
- Freelist page identification in the WAL

Known Issues:

- Overflow Records in the WAL are not completely reconstructed
.
""")

    start_time = datetime.datetime.now()
      
    print(f"Database Analysis Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    db_records, db_recoveredrecords = parse_sqlite_file(db_file)

    if wal_file:
        wal_records, wal_recoveredrecords = parse_wal_file(wal_file, db_file)
        combined_records = db_records + wal_records
        combined_recoveredrecords = db_recoveredrecords + wal_recoveredrecords
    else:
        combined_records = db_records
        combined_recoveredrecords = db_recoveredrecords

    if not combined_records:
        print("[!] No Records Extracted!")
        return
    
    # Create the output folder 
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    output_file = os.path.join(output_folder, "SQBite_Extraction.sqlite")  
   
    # Write records to SQLite Database
    write_to_sqlite(output_file, db_file, combined_records, combined_recoveredrecords)
    
    #Classify the Record Status
    if args.c: 
        classify_records(output_file) 
        
    # Insta Search 
    if search_term:
        result_file_path = os.path.join(output_folder, f"keywordsearch_{search_term}.txt")
        with open(result_file_path, 'w') as result_file:
            insta_search(output_file, result_file, search_term)

    end_time = datetime.datetime.now()
    print(f"\nDatabase Analysis Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    elapsed_time = end_time - start_time
    hours, remainder = divmod(elapsed_time.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Total execution time: {int(hours):02d}:{int(minutes):02d}:{seconds:.2f}")
    print(f"Output saved to {os.path.abspath(output_folder)}")

if __name__ == "__main__":
    tool_name = "Tool Name: SQBite"
    description = (
        "Description: This python script developed by Spyder Forensics LLC parses "
        "records from the SQLite Main database file and Write-Ahead Logs."
    )
    usage = (
        "Usage Example: python SQBite.py -i C:\\Evidence\\mmssms.db "
        "-w C:\\Evidence\\mmssms.db-wal -o C:\\Reports\\mmssms_extraction "
        "-c -s spyder"
    )

    parser = argparse.ArgumentParser(
        description=f"{tool_name}\n{description}\n", 
        epilog=usage, 
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-i', dest="db_file", metavar='db_path', required=True, help="Path to the SQLite main database file.")
    parser.add_argument('-w', dest="wal_file", metavar='wal_path', required=False, help="(Optional) Path to the SQLite WAL file.")
    parser.add_argument('-c', action='store_true', required=False, help="(Optional) Classify Record Status i.e Active, Duplicate, Modified/RowID Reuse, Deleted")
    parser.add_argument('-s', dest="search_term", metavar='search_term', required=False, help="(Optional) Insta Search a keyword across the database")
    parser.add_argument('-o', dest="output_folder", metavar='output_folder', required=True, help="Specify the location to output results")
    
    args = parser.parse_args()
    
    _main(args.db_file, args.wal_file, args.output_folder, args.search_term)


