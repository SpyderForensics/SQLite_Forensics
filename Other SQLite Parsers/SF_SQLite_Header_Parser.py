#This python script extracts and interprets the header information in an 
#SQLite database file and can export the information into a CSV file
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
# v1.0 2024-05-23
# v1.1 2024-06-24
#   -Shortened the width of the pretty table columns to display better on lower resolution screens
#   -Fixed an issue with CSV writer where there was no escape character set
# v1.2 2024-08-19
#   -Fixed a syntax warning on the help page due to the \ in the folder paths being interpreted as escape characters
#   -Updated Examiner Tips 
# v1.3 2025-11-15
#   -Removed PrettyTable module
#   -Updated Examiner Tips

import argparse
import os
import struct
import textwrap
import csv
import logging


def setup_logger(filename):
    logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z (UTC %z)')
    return logging.getLogger()


def print_table_console(rows):
    """Prints header rows in a simple aligned text format"""
    headers = ["Header Entry", "Value", "Offset", "Length", "Description", "Examiner Tip"]
    widths = [28, 20, 12, 12, 50, 100]

    # Print header
    line = ""
    for h, w in zip(headers, widths):
        line += h.ljust(w)
    print(line)
    print("-" * sum(widths))

    for row in rows:
        line = ""
        line += row[0].ljust(widths[0])
        line += str(row[1]).ljust(widths[1])
        line += row[2].ljust(widths[2])
        line += row[3].ljust(widths[3])
        line += row[4].ljust(widths[4])
        line += row[5].ljust(widths[5])
        print(line)


def parse_header(db_file, output_file=None):
    try:
        db_file = os.path.abspath(db_file)
        logger.info("Script: SQLite Main Database File Header Parser")
        logger.info("Author: Spyder Forensics Training")
        logger.info("Website: www.spyderforensics.com")
        logger.info("Script Executed")
        logger.info(f"Input filename: {os.path.basename(db_file)}")
        logger.info(f"Input file full path: {db_file}")
        
        with open(db_file, 'rb') as file:

            magic_string = file.read(16)
            if magic_string != b'SQLite format 3\x00':
                print(f"Error: '{db_file}' is not a valid SQLite database file.")
                logger.error(f"Error: '{db_file}' is not a valid SQLite database file.")
                return

            file.seek(0)
            header_data = file.read(100)

            database_page_size = struct.unpack('>H', header_data[16:18])[0]
            page_size = "65536" if database_page_size == 1 else database_page_size
            Journal_Mode = "Rollback Journal" if (header_data[18], header_data[19]) == (1, 1) else "Write Ahead Log" if (header_data[18], header_data[19]) == (2, 2) else "unknown"
            bytes_reserved_per_page = header_data[20]
            maximum_payload_size = struct.unpack('>b', header_data[21:22])[0]
            minimum_payload_size = struct.unpack('>b', header_data[22:23])[0]
            leaf_payload_size = struct.unpack('>b', header_data[23:24])[0]
            file_change_counter = struct.unpack('>i', header_data[24:28])[0]
            database_size = struct.unpack('>i', header_data[28:32])[0]
            first_freelist_trunk_page = struct.unpack('>i', header_data[32:36])[0]
            number_of_freelist_pages = struct.unpack('>i', header_data[36:40])[0]
            schema_cookie = struct.unpack('>i', header_data[40:44])[0]
            schema_format_number = struct.unpack('>i', header_data[44:48])[0]
            default_page_cache_size = struct.unpack('>i', header_data[48:52])[0]
            auto_vacuum = struct.unpack('>i', header_data[52:56])[0]
            database_text_encoding = struct.unpack('>i', header_data[56:60])[0]
            text_encoding = ("UTF-8" if database_text_encoding == 1 else "UTF-16 LE" if database_text_encoding == 2 else "UTF-16 BE" if database_text_encoding == 3 else "unknown")
            user_version = struct.unpack('>i', header_data[60:64])[0]
            incremental_vacuum_mode = struct.unpack('>i', header_data[64:68])[0]
            application_id = struct.unpack('>i', header_data[68:72])[0]
            unused_bytes = header_data[72:92]
            version_valid_for = struct.unpack('>i', header_data[92:96])[0]
            sqlite_version_number = struct.unpack('>i', header_data[96:100])[0]

            print(r"""
   _____                 _             ______                       _          
  / ____|               | |           |  ____|                     (_)         
 | (___  _ __  _   _  __| | ___ _ __  | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
  \___ \| '_ \| | | |/ _` |/ _ \ '__| |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
  ____) | |_) | |_| | (_| |  __/ |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 |_____/| .__/ \__, |\__,_|\___|_|    |_|  \___/|_|  \___|_| |_|___/_|\___|___/
        | |     __/ |                                                          
        |_|    |___/    

SQLite Main Database File Header Parser
Version: 1.3 Nov, 2025
Author: Spyder Forensics Training
Website: www.spyderforensics.com
""")
			
            print(f"{os.path.basename(db_file)} Header Information\n")

            rows = [
                ['Header String', magic_string.decode('utf-8'), '0', '16', 'SQLite Header String', ''],
                ['Page Size', f'{page_size} bytes', '16', '2', 'Size of a database page', ''],
                ['Journal Mode', Journal_Mode, '18-19', '2 ', 'File format read/write version', 'Extract associated journal files if present'],
                ['Bytes Reserved Per Page', bytes_reserved_per_page, '20', '1', 'Bytes reserved at the beginning of each page', ''],
                ['Maximum Payload Size', maximum_payload_size, '21', '1', 'Maximum embedded payload fraction', ''],
                ['Minimum Payload Size', minimum_payload_size, '22', '1', 'Minimum payload size', ''],
                ['Leaf Payload Size', leaf_payload_size, '23', '1', 'Leaf payload size', ''],
                ['File Change Counter', file_change_counter, '24-27', '4', 'Increments when pages are updated', ''],
                ['Database Size', database_size, '28-31', '4', 'Database size in pages', ''],
                ['First Freelist Trunk Page', first_freelist_trunk_page, '32-35', '4', 'First freelist trunk page', 'Trunk page stores freelist entries'],
                ['Number of Freelist Pages', number_of_freelist_pages, '36-39', '4', 'Total freelist pages', 'Includes trunk pages'],
                ['Schema Cookie', schema_cookie, '40-43', '4', 'Incremented on schema change', 'Great for determining if the logical structure of the database changed when app updates'],
                ['Schema Format Number', schema_format_number, '44-47', '4', 'Schema format number', ''],
                ['Default Page Cache Size', default_page_cache_size, '48-51', '4', 'Default page cache size', ''],
                ['Auto Vacuum', auto_vacuum, '52-55', '4', 'If non-zero, auto-vacuum enabled', 'If enabled: no freelist pages unless incremental-vacuum active'],
                ['Text Encoding', text_encoding, '56', '4', 'Database text encoding', ''],
                ['User Version', user_version, '60-63', '4', 'User version number', ''],
                ['Incremental Vacuum Mode', incremental_vacuum_mode, '64-67', '4', 'If non-zero, incremental vacuum enabled', 'Freelist pages may still exist'],
                ['Application ID', application_id, '68-71', '4', 'Application ID', ''],
                ['Unused Bytes', '20 unused bytes', '72-91', '20', 'Reserved for future use', ''],
                ['Version Valid For', version_valid_for, '92-95', '4', 'Version valid for', ''],
                ['SQLite Version Number', sqlite_version_number, '96-99', '4', 'SQLite version number', '']
            ]

            print_table_console(rows)

            # CSV output
            if output_file:
                output_path = os.path.abspath(output_file)
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(['Header Entry', 'Value', 'Offset', 'Length', 'Description', 'Examiner Tip'])
                    for row in rows:
                        writer.writerow(row)

                print(f"\nHeader information exported to: '{output_path}'")
                logger.info(f"Header Information exported to: '{output_path}'")

            else:
                print("\nUse the '-o' switch to export results to a CSV file.")

    except FileNotFoundError:
        print(f"Error: Unable to open the specified file '{db_file}'")
        logger.error(f"Unable to open file '{db_file}'")


tool_name = "Tool Name: SQLite Main Database File Header Parser"
description = "Description: This python script developed by Spyder Forensics LLC extracts and interprets all the informational entries from an SQLite Database File header"
Usage = "Usage Example: SF_SQLite_Header_Parser.py -i C:\\Evidence\\mmssms.db -o C:\\Reports\\mmssms_sqliteheaderinfo.csv."

parser = argparse.ArgumentParser(description=f"{tool_name}\n{description}\n", epilog=Usage, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-i', dest='db_file', metavar='file_path', required=True, help='Enter the path to SQLite Main Database File')
parser.add_argument('-o', dest='output_file', metavar='output_file', help='Specify location to output the CSV file including name')

args = parser.parse_args()

logger = setup_logger(f"{os.path.splitext(args.output_file)[0]}.log") if args.output_file else setup_logger("Spyder_SQLiteHeaderParser.log")

parse_header(args.db_file, args.output_file)
