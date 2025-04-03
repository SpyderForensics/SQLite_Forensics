import sqlite3
from Modules.extracttabledefinitions import extract_table_definitions_from_schema
from Modules.parsesqliteheader import parse_sqlite_header

def clean_row(row):
    """
    Decodes byte strings with handling for BOM and invalid characters,
    but preserves raw bytes for potential BLOB columns.
    """
    cleaned_row = []
    for value in row:
        if isinstance(value, bytes):
            try:
                decoded = value.decode("utf-8-sig").replace("\ufeff", "").replace("ï»¿", "")
                cleaned_row.append(decoded)
            except UnicodeDecodeError:
                cleaned_row.append(value)
        else:
            cleaned_row.append(value)
    return cleaned_row

def write_to_sqlite(output_file, db_file_path, combined_records, combined_recoveredrecords):
    """
    Writes extracted records to a SQLite database, preserving column types.
    """
    if not combined_records:
        print("\n[!] No Records were Extracted")
        return

    print("\n[+] Adding Extracted Records to SQLite Database")

    with open(db_file_path, "rb") as db_file:
        header = parse_sqlite_header(db_file)
        page_size = header["page_size"]
        tables = extract_table_definitions_from_schema(db_file, page_size)

    table_columns = {table["name"]: table["columns"] for table in tables}

    conn = sqlite3.connect(output_file)
    cursor = conn.cursor()

    sqlite_internal_tables = {
        "sqlite_master", "sqlite_sequence", "sqlite_temp_master", "sqlite_stat1", 
        "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"
    }

    base_headers = ["Record_ID", "Source_File", "Frame_Number", "Page_Number", "Record_Status", "Table_Name", "File_Offset", "Row_ID"]
    recovered_headers = ["Source_File", "Frame_Number", "Page_Number", "Page_Type", "Table_Name", "Record_Status", "File_Offset", "Recovered Data"]

    for table_name, extracted_columns in table_columns.items():
        if table_name.lower() in sqlite_internal_tables:
            continue  

        column_headers = base_headers + [col[0] for col in extracted_columns]
        unique_column_headers = []
        added = set()
        for col in column_headers:
            col_clean = col.strip("'\"")
            if col_clean not in added:
                unique_column_headers.append(col_clean)
                added.add(col_clean)

        column_definitions = [
            '"Record_ID" INTEGER PRIMARY KEY',
            '"Source_File" TEXT',
            '"Frame_Number" INTEGER',
            '"Page_Number" INTEGER',
            '"Record_Status" TEXT',
            '"Table_Name" TEXT',
            '"File_Offset" INTEGER',
            '"Row_ID" INTEGER'
        ]
        
        for col_name in unique_column_headers:
            if col_name in {"Record_ID", "Source_File", "Frame_Number", "Page_Number", "Record_Status", "Table_Name", "File_Offset", "Row_ID"}:
                continue
            col_type = next((ctype for cname, ctype in extracted_columns if cname == col_name), "TEXT")
            column_definitions.append(f'"{col_name}" {col_type}')

        
        if len(column_definitions) <= 1:
            print(f"[!] Skipping creation of Table '{table_name}' due to missing valid columns. Definitions: {column_definitions}")
            continue

        create_table = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({", ".join(column_definitions)})'

        cursor.execute(create_table)

    conn.commit()
    # Track max columns for dynamic/freelist/unknown
    max_columns = max((len(clean_row(row)) + 1 - len(base_headers)) for row in combined_records)
    #print(f"[DEBUG] Max columns calculated for dynamic columns: {max_columns}")
    dynamic_columns = [f"Column_{i+1}" for i in range(max_columns)]

    for row in combined_records:
        cleaned_row = clean_row(row)

        if len(cleaned_row) < 5:
            print(f"[!] Skipping row (not enough data): {cleaned_row}")
            continue

        table_name = str(cleaned_row[4])

        if table_name.lower() in sqlite_internal_tables:
            continue

        # Special handling for "freelist" table
        if table_name.lower() == "freelist":
            column_headers = base_headers + dynamic_columns
            column_definitions = '"Record_ID" INTEGER PRIMARY KEY, ' + ", ".join([f'"{col}" TEXT' for col in column_headers if col != "Record_ID"])
            cursor.execute(f'CREATE TABLE IF NOT EXISTS "Freelist" ({column_definitions})')

            # Add missing columns dynamically
            cursor.execute(f'PRAGMA table_info("Freelist")')
            existing_columns = {row[1] for row in cursor.fetchall()}
            missing_columns = set(column_headers) - existing_columns
            for column in missing_columns:
                cursor.execute(f'ALTER TABLE "Freelist" ADD COLUMN "{column}" BLOB')

        # Special handling of unknown table or mismatched schema
        elif table_name not in table_columns or len(cleaned_row) > len(table_columns[table_name]) + len(base_headers):   
            table_name = "unknown"
            column_headers = base_headers + dynamic_columns

            column_definitions = '"Record_ID" INTEGER PRIMARY KEY, ' + ", ".join([f'"{col}" TEXT' for col in column_headers if col != "Record_ID"])
            cursor.execute(f'CREATE TABLE IF NOT EXISTS "Unknown" ({column_definitions})')

            cursor.execute(f'PRAGMA table_info("Unknown")')
            existing_columns = {row[1] for row in cursor.fetchall()}
            missing_columns = set(column_headers) - existing_columns
            for column in missing_columns:
                cursor.execute(f'ALTER TABLE "Unknown" ADD COLUMN "{column}" BLOB')

        else:
            extracted_columns = table_columns[table_name]
            column_headers = base_headers + extracted_columns

        insert_columns = [col[0] if isinstance(col, tuple) else col for col in column_headers if col != "Record_ID"]
        insert_columns = [col.strip("'\"") for col in insert_columns]

        expected_column_count = len(insert_columns)
        padded_row = cleaned_row[:expected_column_count] 
        padded_row += [''] * (expected_column_count - len(padded_row)) 

        placeholders = ", ".join(["?"] * expected_column_count)
        quoted_columns = ", ".join([f'"{col}"' for col in insert_columns])
        table_target = table_name
        insert_query = f'INSERT INTO "{table_target}" ({quoted_columns}) VALUES ({placeholders})'

        try:
            cursor.execute(insert_query, padded_row)
        except sqlite3.ProgrammingError as e:
            print(f"[-] Error inserting into {table_name}: {e}")
            continue

    recovered_column_names = [
        "Record_ID", "Source_File", "Frame_Number", "Page_Number",
        "Page_Type", "Table_Name", "Record_Status", "File_Offset", "Recovered Data"
    ]

    recovered_column_defs = [
        '"Record_ID" INTEGER PRIMARY KEY',
        '"Source_File" TEXT',
        '"Frame_Number" INTEGER',
        '"Page_Number" INTEGER',
        '"Page_Type" TEXT',
        '"Table_Name" TEXT',
        '"Record_Status" TEXT',
        '"File_Offset" INTEGER',
        '"Recovered Data" TEXT'
    ]

    recovered_definitions_str = ", ".join(recovered_column_defs)
    cursor.execute(f'CREATE TABLE IF NOT EXISTS "Recovered_Records" ({recovered_definitions_str})')

    # Insert records into Recovered_Records table
    for row in combined_recoveredrecords:
        cleaned_row = clean_row(row)

        if len(cleaned_row) < 5:
            print(f"[!] Skipping recovered row (not enough data): {cleaned_row}")
            continue

        table_name = cleaned_row[3]  

        if table_name.lower() in sqlite_internal_tables:
            continue

        insert_columns = [col for col in recovered_column_names if col != "Record_ID"]  
        insert_columns = [col.strip("'\"") for col in insert_columns]

        expected_column_count = len(insert_columns)
        padded_row = cleaned_row[:expected_column_count] 
        padded_row += [''] * (expected_column_count - len(padded_row)) 

        placeholders = ", ".join(["?"] * expected_column_count)
        quoted_columns = ", ".join([f'"{col}"' for col in insert_columns])
        insert_query = f'INSERT INTO "Recovered_Records" ({quoted_columns}) VALUES ({placeholders})'

        try:
            cursor.execute(insert_query, padded_row)
        except sqlite3.ProgrammingError as e:
            print(f"[-] Error inserting into Recovered_Records: {e}")
            continue

    conn.commit()
    print("[+] Extracted Records succesfully added to SQLite Database")
    conn.close()





