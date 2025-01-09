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


import os
import argparse
import datetime
from Modules.parse_sqlite_file import parse_sqlite_file
from Modules.parse_wal_file import parse_wal_file
from Modules.output_csv import write_to_csv

def _main(db_file, wal_file, output_file):
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

Version: Alpha Jan, 2025
Author: Spyder Forensics Training
Website: www.spyderforensics.com

Warning: This is the Alpha code please validate the results (You should always validate anyway)

Note: Table Assignments from the WAL file should be verfied

Not Currently Supported: 

- Parsing Freelist Pages
- Parsing of Index B-trees (WITHOUT ROWID Tables are skipped as they use Index B-trees)
- Parsing of Pointer Map Pages
- Recovering Records from Freeblocks and Page Unallocated Space

Known Issues:

- Overflow Records in the WAL are not completely reconstructed
.
"""
    )
    
    print(f"Database Analysis Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    db_rows = parse_sqlite_file(db_file)
    
    if wal_file:
        wal_rows = parse_wal_file(wal_file, db_file)
        combined_rows = db_rows + wal_rows
    else:
        combined_rows = db_rows

    write_to_csv(output_file, combined_rows)

    print(f"\nDatabase Analysis Completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output saved to {os.path.abspath(output_file)}")



if __name__ == "__main__":
    tool_name = "Tool Name: SQBite"
    description = (
        "Description: This python script developed by Spyder Forensics LLC parses "
        "records from the SQLite Main database file and Write-Ahead Logs."
    )
    usage = (
        "Usage Example: python SQBite.py -i C:\\Evidence\\mmssms.db "
        "-w C:\\Evidence\\mmssms.db-wal -o C:\\Reports\\mmssms_extraction.csv."
    )

    parser = argparse.ArgumentParser(
        description=f"{tool_name}\n{description}\n", 
        epilog=usage, 
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-i', dest="db_file", metavar='db_path', required=True, help="Path to the SQLite main database file.")
    parser.add_argument('-w', dest="wal_file", metavar='wal_path', required=False, help="(Optional) Path to the SQLite WAL file.")
    parser.add_argument('-o', dest="output_file", metavar='output_file', required=True, help="Specify the location to output the CSV file including the name.")
    
    args = parser.parse_args()
    _main(args.db_file, args.wal_file, args.output_file)


