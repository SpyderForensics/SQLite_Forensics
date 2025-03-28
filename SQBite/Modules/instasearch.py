import os
import sqlite3
import argparse

def insta_search(output_file, result_file, search_term):
    conn = sqlite3.connect(output_file)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    table_names = [row[0] for row in cursor.fetchall()]

    print(f"\n[+] Searching for keyword: '{search_term}' in {len(table_names)} tables...\n")
    write_txt(f"Search Results for keyword: '{search_term}'", result_file)
    
    # Loop through each table and search for the keyword
    for table in table_names:
        matches = search_keyword_in_table(conn, table, search_term)
        
        hit_count = 0
        
        if matches:
            write_txt(f"Table: '{table}'", result_file)
            
            for row_id, record_status, matched_columns in matches:
                hit_count += 1
                
                write_txt(f"Record_ID: {row_id}", result_file)
                write_txt(f"Record Status: {record_status}", result_file)  # Write the Record_Status
                for col_name, content in matched_columns.items():
                    write_txt(f"{col_name}: {content}", result_file)
                write_txt("", result_file)
        
            print(f"[+] {hit_count} hits found in '{table}' table")

    conn.close()

def search_keyword_in_table(conn, table_name, search_term):
    cursor = conn.cursor()

    # Get all columns for the table (including non-text columns)
    all_columns = get_all_columns(cursor, table_name)

    if not all_columns:
        return []

    # Create the WHERE clause for searching
    where_clause = " OR ".join([f'"{col}" LIKE ?' for col in all_columns])
    column_list = ", ".join([f'"{col}"' for col in all_columns])
    
    # Include the rowid and record_status in the SELECT query
    query = f'SELECT rowid, record_status, {column_list} FROM "{table_name}" WHERE {where_clause}'

    try:
        cursor.execute(query, ['%' + search_term + '%'] * len(all_columns))
        matches = cursor.fetchall()
    except Exception as e:
        print(f"[!] Error searching in table '{table_name}': {e}")
        return []

    matching_records = []
    for row in matches:
        rowid = row[0]
        record_status = row[1]
        matched_columns = {}

        # Process matched columns
        for col_name, col_value in zip(all_columns, row[2:]):  # Skip first two columns (rowid, record_status)
            if col_value and search_term.lower() in str(col_value).lower():
                matched_columns[col_name] = col_value

        # Only add matched records to the list
        if matched_columns:
            matching_records.append((rowid, record_status, matched_columns))

    return matching_records

def get_all_columns(cursor, table_name):
    """Returns a list of all columns in the table."""
    cursor.execute(f'PRAGMA table_info("{table_name}")')
    return [row[1] for row in cursor.fetchall()] 

def write_txt(text, file=None):
    """Writes Search Results to Text File"""
    try:
        if file:
            file.write(text.encode('utf-8', errors='ignore').decode('utf-8') + "\n")
        else:
            print(text)
    except UnicodeEncodeError:
        text = text.encode('utf-8', 'replace').decode('utf-8')
        if file:
            file.write(text + "\n")
        else:
            print(text)
