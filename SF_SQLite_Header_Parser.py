#This python script extracts and interprets the header information in an 
#SQLite Main database file and can export the information into a CSV file
#
#
#Copyright(C) 2024 Spyder Forensics LLC (www.spyderforensics.com)
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
#You view the GNU General Public License at <https://www.gnu.org/licenses/>.
#
# Version History:
# v1.0 2024-05-23
# v1.1 2024-06-24
#   -Shortened the width of the pretty table columns to display better on lower resolution screens
#   -Fixed an issue with CSV writer where there was no escape character set

import argparse
import os
import struct
import textwrap
import csv
import logging
from prettytable import PrettyTable

def setup_logger(filename):
    logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z (UTC %z)')
    return logging.getLogger()

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
            #checks if the input file is a valid SQLite database 
            if magic_string != b'SQLite format 3\x00':
                print(f"Error: '{db_file}' is not a valid SQLite database file.")
                logger.error(f"Error: '{db_file}' is not a valid SQLite database file.")
                return
				
            # Reset file pointer to the beginning of the file
            file.seek(0)
            #Read the first 100 bytes of the file
            header_data = file.read(100)
            #extract the informational entries as Big Endian values
            database_page_size = struct.unpack('>H', header_data[16:18])[0]
            #database page size is a power of 2 between 512 and 65546. 65536 does not fit as Big Endian integer so return 65536 when the value is Big Endian 1
            page_size = ("65536" if database_page_size == 1 else database_page_size)
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
Version: 1.0 May, 2024
Author: Spyder Forensics Training
Website: www.spyderforensics.com
""")
            print(f"{os.path.basename(db_file)} Header Information")
            #Creates a pretty table to display in the console (This is more for training purposes)
            table = PrettyTable(['Header Entry', 'Value', 'File Offset', 'Length (bytes)', 'Description', 'Examiner Tip'])
            table.align = 'l'

            table.add_row(['Header String', magic_string.decode('utf-8'), '0', '16', 'SQLite Header String',''],divider=True)
            table.add_row(['Page Size', f'{page_size} bytes', '16', '2', 'Size of a database page',''],divider=True)
            table.add_row(['Journal Mode', Journal_Mode, '18-19', '2 (1 byte each)', 'The file format read and write versions at file offset 18 and 19 determines the journalling method','If there is a journal file (-wal or -journal) in the same directory as the main database file ensure they are examined seperatley to get all states of the database!'],divider=True)
            table.add_row(['Bytes Reserved Per Page', bytes_reserved_per_page, '20', '1', 'Number of bytes reserved at the beginning of each page',''],divider=True)
            table.add_row(['Maximum Payload Size', maximum_payload_size, '21', '1', 'Maximum embedded payload fraction',''],divider=True)
            table.add_row(['Minimum Payload Size', minimum_payload_size, '22', '1', 'Minimum payload size',''],divider=True)
            table.add_row(['Leaf Payload Size', leaf_payload_size, '23', '1', 'Leaf payload size',''],divider=True)
            table.add_row(['File Change Counter', file_change_counter, '24-27', '4', 'Integer that increments when one or more pages are updated in the main database file',''],divider=True)
            table.add_row(['Database Size', database_size, '28-31', '4', 'Database size in pages',''],divider=True)
            table.add_row(['First Freelist Trunk Page', first_freelist_trunk_page, '32-35', '4', 'Page number of the first freelist trunk page','The Trunk Page contains a listing of freelist pages'],divider=True)
            table.add_row(['Number of Freelist Pages', number_of_freelist_pages, '36-39', '4', 'Total number of freelist pages','This value includes the Freelist Trunk Pages'],divider=True)
            table.add_row(['Schema Cookie', schema_cookie, '40-43', '4', 'Integer that increments when there is a database schema change',r"A change in the database schema indicates that the app developer changed someting in the database construction which can often cause parsers to break"],divider=True)
            table.add_row(['Schema Format Number', schema_format_number, '44-47', '4', 'The Schema Format Number',''],divider=True)
            table.add_row(['Default Page Cache Size', default_page_cache_size, '48-51', '4', 'Default page cache size',''],divider=True)
            table.add_row(['Auto Vacuum', auto_vacuum, '52-55', '4', 'If the value is a non-zero value auto-vacuum is enabled and the value signifies the largest root B-Tree page','If auto-vacuum is enabled there will be no Freelist Pages!'],divider=True)
            table.add_row(['Text Encoding', text_encoding, '56', '4', 'Encoding used for text strings',''],divider=True)
            table.add_row(['User Version', user_version, '60-63', '4', 'User Version Number',''],divider=True)
            table.add_row(['Incremental Vacuum Mode', incremental_vacuum_mode, '64-67', '4', 'If the value is a non-zero value incremental-vacuum is enabled','There maybe some freelist pages'],divider=True)
            table.add_row(['Application ID', application_id, '68-71', '4', 'Application ID',''],divider=True)
            table.add_row(['Unused Bytes', '20 unused bytes', '88-91', '4', 'Unused bytes reserved for future use',''],divider=True)
            table.add_row(['Version Valid For', version_valid_for, '92-95', '4', 'Version Valid For',''],divider=True)
            table.add_row(['SQLite Version Number', sqlite_version_number, '96-99', '4', 'SQLite Version Number',''],divider=True)

            rows_without_wrapping = []
            for row in table._rows:
                row_values = [str(col).strip() if isinstance(col, str) else col for col in row]
                rows_without_wrapping.append(row_values)

            for row in table._rows:
                for i in range(4, 6):
                    if len(row) > i:
                        row[i] = textwrap.fill(row[i], width=40)

            print(table)
            #If the -o switch is used the information from the pretty table is exported to a csv file. The pretty table formatting is ignored
            if output_file:
                output_path = os.path.abspath(output_file)
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(['Header Entry', 'Value', 'File Offset', 'Length', 'Description', 'Examiner Tip'])
                    for row in rows_without_wrapping:
                        writer.writerow(row)

                print(f"{os.path.basename(db_file)} Header Information successfully exported to:'{output_path}'.")
                logger.info(f"{os.path.basename(db_file)} Header Information successfully exported to:'{output_path}'")
                
            else:
                print("Use the '-o' switch to output the header information to a CSV file.")
                logger.info("No output file provided. Use the '-o' switch to output the header information to a CSV file.")

    except FileNotFoundError:
        print(f"Error: Unable to open the specified file '{db_file}'")
        logger.error(f"Error: Unable to open the specified file '{db_file}'")
tool_name = "Tool Name: SQLite Main Database File Header Parser"
description = "Description: This python script developed by Spyder Forensics LLC extracts and interprets all the informational entries from an SQLite Main Database File header"
Usage = "Usage Example: SF_SQLite_Header_Parser.py -i C:\Evidence\mmssms.db -o C:\Reports\mmssms_sqliteheaderinfo.csv."

parser = argparse.ArgumentParser(description=f"{tool_name}\n{description}\n", epilog=Usage, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-i', dest='db_file', metavar='file_path', required=True, help='Enter the path to SQLite Main Database File')
parser.add_argument('-o', dest='output_file', metavar='output_file', help='Specify the location to output the CSV file including name')
args = parser.parse_args()

logger = setup_logger(f"{os.path.splitext(args.output_file)[0]}.log") if args.output_file else setup_logger("Spyder_SQLiteHeaderParser.log")
parse_header(args.db_file, args.output_file)


