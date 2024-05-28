#This python script extracts information about each page in an 
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
#You can view the GNU General Public License at <https://www.gnu.org/licenses/>.
#
# Version History:
# v1.0 2024-05-28

import argparse
import os
import struct
import textwrap
import csv
import logging
import math
from prettytable import PrettyTable

#This function creates a logger
def setup_logger(filename):
    logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z (UTC %z)')
    return logging.getLogger()

#This function iterates through every page in the main database file and determines what type of page it is
#Todo: Add an elif to identify lock byte pages, currently will be returned as an unknown page type. A single lock byte page is present in the database when the database file is greater than 1 GB  
def read_page(file, page_size, auto_vacuum, first_freelist_trunk, freelist_trunk_pages, freelist_pages, pointer_pages):
    page_number = 0
    while True:
        #Reads the data on the page and stores as a variable
        pagedata = file.read(page_size)
        #Breaks the loop when the end of the file is reached
        if not pagedata:
            break
        #Increases page number by 1
        page_number += 1
        #Reads the page flag
        page_flag = struct.unpack('>b', pagedata[0:1])[0]
        #Checks to see if auto vacuum is is a non-zero value and the page number is 2 and sets the page type as Pointer Map page
        if auto_vacuum > 0 and (page_number == 2 or page_number in pointer_pages):
            page_type = "Pointer Map Page"
        #Checks to see if the page number is freelist trunk, if its then the page type is a Freelist Trunk Page
        elif page_number == first_freelist_trunk or page_number in freelist_trunk_pages:
            page_type = "Freelist Trunk Page"
        #Checks to see if the page number is in the list of freelist_pages
        elif page_number in freelist_pages:
            #Checks to see if the page has data. This would be in the scenario where secure_delete is enabled causing the whole page to be zero'd before the page is moved to the freelist
            if all(byte == 0 for byte in pagedata):
                page_type = "Freelist Leaf Page: Secure_Deleted"
            else:
            #If the page is in the list of freelist pages then determine the previous use of the page by reading the flag
                if page_flag == 13: 
                    page_type = "Freelist Leaf Page: B-tree Table Leaf Page"
                elif page_flag == 5: 
                    page_type = "Freelist Leaf Page: B-tree Table Interior Page"
                elif page_flag == 10: 
                    page_type = "Freelist Leaf Page: B-tree Index Leaf Page"
                elif page_flag == 2: 
                    page_type = "Freelist Leaf Page: B-tree Index Interior Page"
                elif page_flag == 0: 
                    page_type = "Freelist Leaf Page: Payload Overflow page"
                else: 
                    page_type = "Freelist Leaf Page: Last use is unknown"                 
        #Checks to see if the page flag is 83 and the page number is 1 and sets the page type as Main database file header and first page of schema
        elif page_flag == 83 and page_number == 1: 
            page_type = "Main Database File Header + First Page of Database Schema"
        #Checks to see if the page flag is 13 and sets the page type as B Tree Table Leaf
        elif page_flag == 13: 
            page_type = "B-tree Table Leaf Page"
        #Checks to see if the page flag is 5 and sets the page type as B Tree Table Interior
        elif page_flag == 5: 
            page_type = "B-tree Table Interior Page"
        #Checks to see if the page flag is 10 and sets the page type as B Tree Index Leaf
        elif page_flag == 10: 
            page_type = "B-tree Index Leaf Page"
        #Checks to see if the page flag is 2 and sets the page type as B Tree Index Interior
        elif page_flag == 2: 
            page_type = "B-tree Index Interior Page"
        #Checks to see if the page flag is 0 
        elif page_flag == 0:
            #Checks to see if all bytes are zero, if it is then sets the page type as Unknown: Empty Page. This is to account for empty pages that have been observed at the end of the database file. 
            if all(byte == 0 for byte in pagedata):
                page_type = "Unknown: Empty Page"
            #If there is data then set page type as payload overflow page
            else:        
                page_type = "Payload Overflow Page"
        #Catch all if doesn't match any other the page flags referenced above
        else: 
            page_type = "Unknown Page Type"
        #uncomment below line if you want an entry added in the log when the page information has been extracted
        #logger.info(f"Page {page_number} analysis complete")                              
        yield (page_number, page_flag, page_type)

#This function calculates the page number for all pointer map pages.
def calculate_pointermappages (auto_vacuum, page_size, total_pages):
    pointer_pages = []
    #Checks if auto_vaccum is enabled
    if auto_vacuum > 0 :
        #Variable to store the list of pointer map pages
        #Sets the pointer counter at 1 as we known the first pointer map
        pointer_counter = 1
        #Calulates the number of 5-byte entries that can be stored on the page
        pointer_entries = math.floor(page_size/5)
        #Sets pointer number to 0
        pointer_number = 0
        #While the pointer_number is less than or equal to the total number of pages in the database do this
        while pointer_number <= total_pages:
            #Calculates the pointer number
            pointer_number = ((pointer_entries * pointer_counter) + 2 + pointer_counter)
            #Breaks the loop when the pointer_number is greater than total pages.
            #Added this due to some wierd anonmaly where the last pointer number generated was higher than the total_pages
            if pointer_number > total_pages:
                break
            #Adds the pointer number to the Pointer Page list
            pointer_pages.append(pointer_number)
            #Increments the pointer counter before the loop
            pointer_counter += 1
    return pointer_pages
            
        
    
#This function iterates through each freelist trunk page and extracts the freelist page numbers
def extract_freelist_pagenumbers(file, page_size, first_freelist_trunk):
    #Variable to store the list of freelist page numbers 
    freelist_pages = []
    #Variable to store the list of freelist trunk pages
    freelist_trunk_pages = []
    #Sets the first trunk page number which we grabbed from the file header
    freelist_trunk = first_freelist_trunk
    while freelist_trunk != 0:
        # Seek to the file offset for the freelist trunk page
        file.seek((freelist_trunk - 1) * page_size)
        #Reads the first 4 bytes to identify the next trunk page
        next_trunk_page = file.read(4)
        freelist_trunk_pages.append(next_trunk_page)
        #Reads the second 4 bytes to identify the number of entries in the freelist page array
        num_entries = struct.unpack('>I', file.read(4))[0]             
        #Reads the page numbers in the freelist array
        for _ in range(num_entries):
            #Reads the 4-byte page entry
            entry_page_number = struct.unpack('>I', file.read(4))[0]
            #adds the page number to the freelist page list
            freelist_pages.append(entry_page_number)
        #Updates the freelist_trunk varaible to next trunk page before looping
        freelist_trunk = struct.unpack('>I', next_trunk_page)[0]
    return freelist_pages, freelist_trunk_pages

#This function extracts information from the main database file header 
def header_info(file, header_data):
    #Reads offset 16-17 in the file header to determine page size 
    database_page_size = struct.unpack('>H', header_data[16:18])[0]
    #Checks to see if the value = 1, if it does then page size = 65536 else just return the original value. This is here because 65536 cannot fit as a 2 byte integer and is a valid SQlite page size.
    if database_page_size == 1:
        page_size = 65536
    else:
        page_size = database_page_size
    #Determine total pages in the database
    database_size = struct.unpack('>i', header_data[28:32])[0]
    #While I was testing various databases, I happened to find a database where auto vacuum was enabled and the database size from the header was zero even though it had 4942 pages (really wierd). I added an if statement where it will calculate the number of pages in database by seeking to the end of the file then dividing the number of bytes by the page size.
    if database_size == 0:
        file.seek(0, 2)
        total_pages = file.tell()/page_size
    else: total_pages = database_size    
    # Determine the freelist trunk page if it exists
    first_freelist_trunk = struct.unpack('>i', header_data[32:36])[0]
    # Determine if auto vacuum is enabled
    auto_vacuum = struct.unpack('>i', header_data[52:56])[0]              
    return page_size, total_pages, first_freelist_trunk, auto_vacuum, 

def main(db_file, output_file):
    try:
        db_file = os.path.abspath(db_file)
        logger.info("Script: SQLite Page Information Extractor")
        logger.info("Author: Spyder Forensics Training")
        logger.info("Website: www.spyderforensics.com")
        logger.info("Script Executed")
        logger.info(f"Input filename: {os.path.basename(db_file)}")
        logger.info(f"Input file full path: {db_file}")
        with open(db_file, 'rb') as file:
            # checks if the input file is a valid SQLite database
            magic_string = file.read(16)
            if magic_string != b'SQLite format 3\x00':
                print(f"Error: '{db_file}' is not a valid SQLite database file.")
                logger.error(f"Error: '{db_file}' is not a valid SQLite database file.")
                return                       
            file.seek(0)
            #Reads the header data
            header_data = file.read(100)
            page_size, total_pages, first_freelist_trunk, auto_vacuum = header_info(file, header_data)
            if not page_size:
                print("Error: Unable to determine page size.")
                logger.error("Error: Unable to determine page size.")
                return
            pointer_pages = calculate_pointermappages(auto_vacuum, page_size, total_pages)               
            freelist_pages, freelist_trunk_pages = extract_freelist_pagenumbers(file, page_size, first_freelist_trunk)
            file.seek(0)
            print(r"""
   _____                 _             ______                       _          
  / ____|               | |           |  ____|                     (_)         
 | (___  _ __  _   _  __| | ___ _ __  | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
  \___ \| '_ \| | | |/ _` |/ _ \ '__| |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
  ____) | |_) | |_| | (_| |  __/ |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 |_____/| .__/ \__, |\__,_|\___|_|    |_|  \___/|_|  \___|_| |_|___/_|\___|___/
        | |     __/ |                                                          
        |_|    |___/    

SQLite Page Information Extractor
Version: 1.0 May, 2024
Author: Spyder Forensics Training
Website: www.spyderforensics.com
""")
            print(f"{os.path.basename(db_file)} Page Information")
            #Creates a Pretty Table which is displayed in the console
            table = PrettyTable(["Page Number", "File Offset", "Page Flag", "Page Type"])
            table.align = 'l'
            file_offset = 0
            for page_number, page_flag, page_type in read_page(file, page_size, auto_vacuum, first_freelist_trunk, freelist_trunk_pages, freelist_pages, pointer_pages):
                table.add_row([page_number, file_offset, page_flag, page_type])
                file_offset += page_size  # Increments file offset by page size
            #Stores the table information without any formatting so it can be used in the CSV output
            rows_without_wrapping = []
            for row in table._rows:
                row_values = [str(col).strip() if isinstance(col, str) else col for col in row]
                rows_without_wrapping.append(row_values)
            print(table)
            #If the -o switch is used the information from the pretty table is exported to a csv file. The pretty table formatting is ignored
            if output_file:
                output_path = os.path.abspath(output_file)
                with open(output_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Page Number", "File Offset", "Page Flag", "Page Type"])
                    for row in rows_without_wrapping:
                        writer.writerow(row)
                print("Analysis of All Pages Complete!")
                logger.info("Analysis of All Pages Complete")
                print(f"SQLite Page Information for {os.path.basename(db_file)} successfully exported to:{output_path}")
                logger.info(f"SQLite Page Information {os.path.basename(db_file)} successfully exported to:{output_path}")
                
            else:
                print("Analysis of All Pages Complete!")
                logger.info("Analysis of All Pages Complete")
                print("Use the '-o' switch to output the header information to a CSV file.")
                logger.info("No output file provided. Use the '-o' switch to output the SQLite Page Information to a CSV file.")
    except FileNotFoundError:
        print(f"Error: Unable to open the specified file '{db_file}'")
        logger.error(f"Error: Unable to open the specified file '{db_file}'")

tool_name = "Tool Name: SQLite Page Infromation Extractor"
description = "Description: This python script developed by Spyder Forensics LLC extracts information about all pages in an SQLite Main Database File "
Usage = "Usage Example: SF_Page_Info_Parser.py -i C:\\Evidence\\mmssms.db -o C:\\Reports\\mmssms_sqlitepageinfo.txt"

parser = argparse.ArgumentParser(description=f"{tool_name}\n{description}\n", epilog=Usage, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-i', dest='db_file', metavar='file_path', required=True, help='Enter the Path to SQLite Main Database File')
parser.add_argument('-o', dest='output_file', metavar='output_file', help='Specify the location to output the CSV file including name')
args = parser.parse_args()
logger = setup_logger(f"{os.path.splitext(args.output_file)[0]}.log") if args.output_file else setup_logger("Spyder_SQLitePageInfo.log")
main(args.db_file, args.output_file)
