import os
import sqlite3
import string 

def insta_search(output_file, result_file, search_term):
    conn = sqlite3.connect(output_file)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    table_names = [row[0] for row in cursor.fetchall()]

    print(f"\n[+] Searching for keyword: '{search_term}' in {len(table_names)} tables...\n")
    write_txt(f"Search Results for keyword: {search_term}\n", result_file)
    total_hits = 0
    # Loop through each table and search for the keyword
    for table in table_names:
        matches = search_keyword_in_table(conn, table, search_term)
        
        hit_count = 0
        
        if matches:
           
            for table_name, row_id, record_status, matched_columns in matches:
                hit_count += 1
                total_hits += 1
                
                write_txt(f"Table: {table_name}", result_file)
                write_txt(f"Record_ID: {row_id}", result_file)
                write_txt(f"Record Status: {record_status}", result_file) 
                for col_name, content in matched_columns.items():
                    write_txt(f"{col_name}: {content}", result_file)
                write_txt("", result_file)
        
            print(f"[+] {hit_count} hits found in '{table}' table")
            
    print(f"\n[+] Finished Searching for keyword: '{search_term}'")
    print(f"[+] Total keyword hits: {total_hits}")
    
    conn.close()

def search_keyword_in_table(conn, table_name, search_term):
    cursor = conn.cursor()

    # Get all columns and their types
    cursor.execute(f'PRAGMA table_info("{table_name}")')
    schema_info = cursor.fetchall()

    if not schema_info:
        return []

    # Ignore SQBite populated columns
    excluded_columns = ["source_file", "frame_number", "page_number", "page_type", "table_name", "record_id", "record_status"]
    all_columns = [row[1] for row in schema_info if row[1].lower() not in excluded_columns]
    column_types = {row[1]: row[2].upper() for row in schema_info}
    

    # Select all columns + rowid and record_status
    column_list = ", ".join([f'"{col}"' for col in all_columns])
    query = f'SELECT record_id, record_status, {column_list} FROM "{table_name}"'

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        print(f"[!] Error querying table '{table_name}': {e}")
        return []

    matching_records = []
    for row in rows:
        record_id = row[0]
        record_status = row[1]
        matched_columns = {}

        for col_name, col_value in zip(all_columns, row[2:]):
            if col_value is None:
                continue
            if isinstance(col_value, bytes):
                try:
                    decoded_value = col_value.decode('utf-8', errors='ignore')
                    printable_data = ''.join(ch for ch in decoded_value if ch in string.printable) #and not ch.isspace())

                    if search_term.lower() in printable_data.lower():
                        matched_columns[col_name] = f'[BLOB] {printable_data}'
                except Exception:
                    continue
            else:
                if search_term.lower() in str(col_value).lower():
                    matched_columns[col_name] = col_value

        if matched_columns:
            matching_records.append((table_name, record_id, record_status, matched_columns))

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
