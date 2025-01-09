#This python script identifies Freelist pages in an SQLite Main database file 
#and provides information about them.
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
# v1.0 2024-06-06


import argparse
import os
import struct
import textwrap
import csv
import logging
from prettytable import PrettyTable

#This function creates a logger
def setup_logger(filename):
    logging.basicConfig(filename=filename, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z (UTC %z)')
    return logging.getLogger()

#This function iterates through freelist trunk pages, extracts the page numbers from the freelist array.
#It also checks the unallocated space at the bottom of the trunk page.
def extract_freelist_pages(file, first_freelist_trunk, page_size):
    #Variable to store the list of freelist trunk page numbers 
    freelist_trunk_pages = [first_freelist_trunk]
    #Variable to store the list of freelist page numbers 
    freelist_pages = []
    #Variable to store the list of trunk unallocated space
    freelist_trunk_unallocated = []
    #Varibale to store the results of the unallocated space checks
    freelist_trunk_unallocated_check = []
    #Sets the first trunk page number which we grabbed from the file header
    freelist_trunk_page = first_freelist_trunk
    while freelist_trunk_page != 0:
        #Go to the physical offset of the freelist trunk page
        file.seek((freelist_trunk_page - 1) * page_size)
        #Reads the first 4 bytes to identify the next trunk page
        next_trunk_page = struct.unpack('>I', file.read(4))[0]
        if next_trunk_page > 0 :
            freelist_trunk_pages.append(next_trunk_page)            
        #Reads the second 4 bytes to identify the number of entries in the freelist page array
        num_entries = struct.unpack('>I', file.read(4))[0]
        #Calculates the length of the freelist page array
        freepagearray = (num_entries*4)
        #Read the page numbers in the freelist page array
        for _ in range(num_entries):
            #Reads the 4-byte page entry
            entry_page_number = struct.unpack('>I', file.read(4))[0]
            #adds the page number to the freelist page list
            freelist_pages.append(entry_page_number)
        #calculates the space left on the page that could contain residual data from the previous use
        trunkunallocatedspace = (page_size-(freepagearray+8))
        #If the value is greater than 1, return number of bytes in the output
        if trunkunallocatedspace !=0: has_trunkunallocated = f'Yes: {trunkunallocatedspace} bytes'
        else: has_trunkunallocated = "No"
        #stores trunk unallocated info
        freelist_trunk_unallocated.append(has_trunkunallocated)
        #Quick byte check to see if there are any non-zero values in unallocated space
        unallocateddata = file.read(trunkunallocatedspace)
        if any(byte != 0 for byte in unallocateddata):
            trunk_unallocatedcheck = "Non-zero values found in page unallocated space"
        else: 
            trunk_unallocatedcheck = "Page unallocated space contains all zero's"
        #Stores the results of the unallocated check
        freelist_trunk_unallocated_check.append(trunk_unallocatedcheck)
        #Updates the freelist_trunk varaible to next trunk page before looping
        freelist_trunk_page = next_trunk_page
    return freelist_pages, freelist_trunk_pages, freelist_trunk_unallocated, freelist_trunk_unallocated_check 
#This function determines the page type for each freelist page in the database
def read_page(file, freelist_pages, page_size):
    # Resets file pointer to 0
    file.seek(0)
    # Runs through each page number identified as a freelist page
    for page_number in freelist_pages:
        # Calculates the physical offset for the page
        file_offset = (page_number - 1) * page_size
        # Sets file pointer to the file offset
        file.seek(file_offset)
        # Reads the page data for the purpose of determining if the page has been secure deleted
        page_data = file.read(page_size)
        # Resets the file pointer to beginning of the page 
        file.seek(file_offset)
        # Reads the first byte to determine page type
        page_flag = struct.unpack('>b', page_data[0:1])[0]
        if page_flag == 13:
            page_type = "B-tree Table Leaf Page"
        elif page_flag == 5:
            page_type = "B-tree Table Interior Page"
        elif page_flag == 10:
            page_type = "B-tree Index Leaf Page"
        elif page_flag == 2:
            page_type = "B-tree Index Interior Page"
        elif page_flag == 0:
            # If the page flag is 0 then the page could either be an overflow page or the page has been secure deleted
            if all(byte == 0 for byte in page_data):
                page_type = "Unknown"
            else:
                page_type = "Payload Overflow Page" 
        else: 
            page_type = "Unknown Page Type"           
                                                   
        yield (page_number, page_type)


        
def extract_freelist_pageinfo(file, freelist_pages, page_size):
    for page_number in freelist_pages:
        file_offset = (page_number - 1) * page_size
        file.seek(file_offset)
        page_flag_data = file.read(1)
        page_flag = struct.unpack('>b', page_flag_data)[0]
        if page_flag in (2, 5):
            file.seek(file_offset)
            # B-tree Interior Pages have 12 byte headers
            interior_header_data = file.read(12)
            freeblock_offset = struct.unpack('>H', interior_header_data[1:3])[0]
            if freeblock_offset == 0: freeblocks = "Yes" 
            else: freeblocks = "No"
            number_allocated_cells = struct.unpack('>H', interior_header_data[3:5])[0]
            start_cells_offset = struct.unpack('>H', interior_header_data[5:7])[0]
            cell_pointer_length = number_allocated_cells * 2 
            file.read(cell_pointer_length)
            unallocatedspace = (start_cells_offset-(12 + cell_pointer_length))
            if unallocatedspace !=0: has_unallocated = f'Yes: {unallocatedspace} bytes'
            else: has_unallocated = "No"
            unallocateddata = file.read(unallocatedspace)
            if any(byte != 0 for byte in unallocateddata):
                page_unallocatedspace = "Non-zero values found in page unallocated space"
            else: page_unallocatedspace = "Page unallocated space contains all zero's"
            freeblock_counter = "N/A"
        elif page_flag in (10, 13):
            leaf_freeblocks = []
            file.seek(file_offset)
            # B-tree Leaf Pages have 8 byte headers
            leaf_header_data = file.read(8)
            freeblock_offset = struct.unpack('>H', leaf_header_data[1:3])[0]
            if freeblock_offset == 0: freeblocks = "Yes" 
            else: freeblocks = "No"
            if freeblock_offset > 0: freeblock_counter = 1
            else: freeblock_counter = 0
            number_allocated_cells = struct.unpack('>H', leaf_header_data[3:5])[0]
            start_cells_offset = struct.unpack('>H', leaf_header_data[5:7])[0]
            cell_pointer_length = number_allocated_cells * 2  
            file.read(cell_pointer_length)
            unallocatedspace = (start_cells_offset-(12 + cell_pointer_length))
            unallocateddata = file.read(unallocatedspace)
            if unallocatedspace !=0: has_unallocated = f'Yes: {unallocatedspace} bytes'
            else: has_unallocated = "No"
            if any(byte != 0 for byte in unallocateddata):
                page_unallocatedspace = "Non-zero values found in page unallocated space"
            else: page_unallocatedspace = "Page unallocated space contains all zero's"
            #count freeblocks            
            freeblock_pointer = freeblock_offset
            # file.seek(file_offset+next_freeblock)
            # freeblock_pointer = struct.unpack('>H', file.read(2))[0]
            while freeblock_pointer != 0:
                freeblock_counter += 1  # Increment counter
                next_freeblock_offset = file_offset + freeblock_pointer
                file.seek(next_freeblock_offset)
                next_freeblock = struct.unpack('>H', file.read(2))[0]
                if next_freeblock > 0:
                    leaf_freeblocks.append(next_freeblock) 
                    freeblock_pointer = next_freeblock
                else:
                    break    
        elif page_flag == 0:
            file.seek(file_offset+4)
            unallocatedspace = file.read(page_size-4)
            number_allocated_cells = "N/A"
            freeblocks = 'N/A'
            freeblock_counter = "N/A"
            has_unallocated = f'N/A'
            if all(byte == 0 for byte in unallocatedspace):
                page_unallocatedspace = "Secure_Deleted"
            else: page_unallocatedspace = "First four bytes store the pointer to next overflow page, all bytes after would have been used to store the overflow for a record"
        else:
            # Handle other page types
            number_allocated_cells = ""
            freeblocks = ""
            freeblock_counter = ""
            has_unallocated = ""
            page_unallocatedspace = ""
            
        yield (number_allocated_cells, freeblocks, has_unallocated, page_unallocatedspace, freeblock_counter)

def _main(db_file, output_file):
    logger.info("Script: SQLite Freepage Checker")
    logger.info("Author: Spyder Forensics Training")
    logger.info("Website: www.spyderforensics.com")
    logger.info("Script Executed")
    logger.info(f"Input filename: {os.path.basename(db_file)}")
    logger.info(f"Input file full path: {(db_file)}")

    try:
        with open(db_file, 'rb') as file:
            magic_string = file.read(16)
            # checks if the input file is a valid SQLite database
            if magic_string != b'SQLite format 3\x00':
                print(f"Error: '{db_file}' is not a valid SQLite database file.")
                logger.error(f"Error: '{db_file}' is not a valid SQLite database file.")
                return

            # Reset file pointer to the beginning of the file
            file.seek(0)
            # Read the first 100 bytes of the file
            header_data = file.read(100)
            # Read the first 4 bytes to determine the database page size
            # Extract the informational entries as Big Endian values
            database_page_size = struct.unpack('>H', header_data[16:18])[0]
            page_size = 65536 if database_page_size == 1 else database_page_size
            first_freelist_trunk = struct.unpack('>i', header_data[32:36])[0]
            freelist_pages, freelist_trunk_pages, freelist_trunk_unallocated, freelist_trunk_unallocated_check = extract_freelist_pages(file, first_freelist_trunk, page_size)
            freelist_page_count = len(freelist_pages)
            freelist_trunk_count = len(freelist_trunk_pages)

            print(r"""
   _____                 _             ______                       _          
  / ____|               | |           |  ____|                     (_)         
 | (___  _ __  _   _  __| | ___ _ __  | |__ ___  _ __ ___ _ __  ___ _  ___ ___ 
  \___ \| '_ \| | | |/ _` |/ _ \ '__| |  __/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
  ____) | |_) | |_| | (_| |  __/ |    | | | (_) | | |  __/ | | \__ \ | (__\__ \
 |_____/| .__/ \__, |\__,_|\___|_|    |_|  \___/|_|  \___|_| |_|___/_|\___|___/
        | |     __/ |                                                          
        |_|    |___/    

SQLite Freelist Page Checker
Version: 1.0 June, 2024
Author: Spyder Forensics Training
Website: www.spyderforensics.com
""")
            print(f"{os.path.basename(db_file)} Freelist Information")
            if first_freelist_trunk != 0: 
                print("Total Freelist Pages:",(freelist_trunk_count+freelist_page_count))
                print("Number of Freelist Trunk Pages:",freelist_trunk_count,"  (Remember Freelist Trunk Pages are Freelist Pages and should be examined as well)")
                print("Number of Freelist Leaf Pages:", freelist_page_count)
                # Create a PrettyTable to display the freelist page information
                table = PrettyTable(["Page_Number","File_Offset","Page_Type","Allocated_Cells","Freeblocks", "Has_Unallocated", "Unallocated_Check"])
                table.align = 'l'
                # Adds Freelist Trunk Page information to the PrettyTable
                for trunk_page, has_trunkunallocated, freelist_trunk_unallocated_check in zip(freelist_trunk_pages, freelist_trunk_unallocated, freelist_trunk_unallocated_check):
                    file_offset = (trunk_page - 1) * page_size
                    table.add_row([trunk_page, file_offset, "Freelist Trunk Page", "Unknown", "Unknown", has_trunkunallocated, freelist_trunk_unallocated_check], divider=True)
                # Adds Freelist Page Information parsed from the Freelist Trunk Pages to the PrettyTable
                for page_number, page_type in read_page(file, freelist_pages, page_size):
                    file_offset = (page_number - 1) * page_size
                    for info in extract_freelist_pageinfo(file, [page_number], page_size):
                        number_allocated_cells, freeblock_counter, has_unallocated, page_unallocatedspace, freeblock_counter = info
                        table.add_row([page_number, file_offset, page_type, number_allocated_cells, freeblock_counter, has_unallocated, page_unallocatedspace], divider=True)
                rows_without_wrapping = []
                for row in table._rows:
                    row_values = [str(col).strip() if isinstance(col, str) else col for col in row]
                    rows_without_wrapping.append(row_values)
                # Wraps the text in pretty table for Unallocated Space column
                for row in table._rows:
                    for i in range(7):
                        if len(row) > i:
                            row[i] = textwrap.fill(str(row[i]), width=100)
                print(table)
                # If the -o switch is used the information from the pretty table is exported to a csv file. The pretty table formatting is ignored
                if output_file:
                    output_path = os.path.abspath(output_file)
                    with open(output_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(["Page Number", "File Offset", "Page Type", "Allocated_Cells", "Freeblocks", "Has_Unallocated", "Unallocated_Check"])
                        for row in rows_without_wrapping:
                            writer.writerow(row)
                    logger.info("Analysis of Freelist Complete")
                    print(f"Freelist Information for {os.path.basename(db_file)} successfully exported to: {output_path}")
                    logger.info(f"Freelist Information for {os.path.basename(db_file)} successfully exported to: {output_path}")
                else: 
                    logger.info("Analysis of Freelist Pages Complete")
                    print("Use the '-o' switch to output the freelist information to a CSV file.")
                    logger.info("No output file provided. Use the '-o' switch to output the Freelist Information to a CSV file.")
            elif first_freelist_trunk == 0:
                print("Analysis of Freelist Pages Complete: No Freelist Pages Found")
                logger.info("Analysis of Freelist Pages Complete: No Freelist Pages Found")

    except Exception as e:
        print(f"An error occurred: {e}")
        logger.error(f"An error occurred: {e}")

 

if __name__ == "__main__":
    tool_name = "Tool Name: SQLite Freelist Page Checker"
    description = "Description: This python script developed by Spyder Forensics LLC extracts information about freelist pages from an SQLite Main database file"
    Usage = "Usage Example: python SF_SQLite_Freelist_checker.py -i C:\\Evidence\\mmssms.db -o C:\\Reports\\mmssms_sqlitefreepageinfo.csv."
    parser = argparse.ArgumentParser(description=f"{tool_name}\n{description}\n", epilog=Usage, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', dest='db_file', metavar='file_path', required=True, help='Enter the Path to SQLite Main Database File')
    parser.add_argument('-o', dest='output_file', metavar='output_file', help='Specify the location to output the CSV file including name')
    args = parser.parse_args()
    logger = setup_logger(f"{os.path.splitext(args.output_file)[0]}.log") if args.output_file else setup_logger("Spyder_SQLiteFreelistInfo.log")

    _main(args.db_file, args.output_file)
