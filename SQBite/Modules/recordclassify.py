import sqlite3

def classify_records(output_file):    
	
    conn = sqlite3.connect(output_file)
    cursor = conn.cursor()
	
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = cursor.fetchall()

    print(f"\n[+] Classifying Records")

    highest_frame_numbers = {}

    for table in tables:
        table_name = table[0]

        if table_name.lower() in ["unknown", "freelist", "recovered_records"]:
            continue

        cursor.execute(f"PRAGMA table_info('{table_name}')")
        columns = [col[1].lower() for col in cursor.fetchall()] 

        if "frame_number" not in columns or "page_number" not in columns:
            print(f"[-] Table '{table_name}' does not have required columns (frame_number, page_number). Skipping.")
            continue

        cursor.execute(f"SELECT page_number, frame_number FROM {table_name}")
        records = cursor.fetchall()

        for page_number, frame_number in records:
            frame_number = 0 if frame_number == "N/A" else int(frame_number)

            if page_number not in highest_frame_numbers:
                highest_frame_numbers[page_number] = frame_number
            else:
                highest_frame_numbers[page_number] = max(highest_frame_numbers[page_number], frame_number)
                
    for table in tables:
        table_name = table[0]

        if table_name.lower() in ["unknown", "freelist", "recovered_records"]:
            continue

        cursor.execute(f"PRAGMA table_info('{table_name}')")
        columns = [col[1].lower() for col in cursor.fetchall()] 

        if "record_status" not in columns or "frame_number" not in columns or "page_number" not in columns:
            continue

        for page_number, highest_frame in highest_frame_numbers.items():
            if highest_frame == 0:
                cursor.execute(f"""
                    SELECT record_id, frame_number FROM {table_name}
                    WHERE page_number = ? AND frame_number = 'N/A'
                """, (page_number,))
            else:
                cursor.execute(f"""
                    SELECT record_id, frame_number FROM {table_name}
                    WHERE page_number = ? AND frame_number = ?
                """, (page_number, highest_frame))

            rows_to_update = cursor.fetchall()

            #print(f"[+] Found {len(rows_to_update)} records for page_number {page_number} with frame_number {highest_frame}")

            for row in rows_to_update:
                record_id = row[0]
                #print(f'Updating record_id: {record_id} with record_status = Active')
                cursor.execute(f"""
                    UPDATE {table_name} SET record_status = ? WHERE record_id = ?
                """, ("Active", record_id))
    conn.commit()
                
    # Classify Records 
    for table in tables:
        table_name = table[0]

        if table_name.lower() in ["unknown", "freelist", "recovered_records"]:
            continue

        cursor.execute(f"PRAGMA table_info('{table_name}')")
        columns = [col[1].lower() for col in cursor.fetchall()] 

        if "record_status" not in columns or "frame_number" not in columns or "page_number" not in columns:
            continue

        for page_number, highest_frame in highest_frame_numbers.items():
            cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE page_number = ? AND frame_number = ?
            """, (page_number, highest_frame))

            highest_frame_records = cursor.fetchall() 

            cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE page_number = ? AND frame_number != ? AND record_status != 'Active'
            """, (page_number, highest_frame))

            non_highest_frame_records = cursor.fetchall()

            for non_highest in non_highest_frame_records:
                non_highest_record_id = non_highest[0]
                non_highest_row_id = non_highest[7]  
                non_highest_data = non_highest[8:]  

                corresponding_highest = next((rec for rec in highest_frame_records if rec[7] == non_highest_row_id), None)
                if not corresponding_highest:
                    cursor.execute(f"""
                        UPDATE {table_name} SET record_status = ? WHERE record_id = ?
                    """, ("Deleted", non_highest_record_id))

                    #print(f"Updated record_id {non_highest_record_id} to 'Deleted' due to missing highest frame.")

                    continue

                highest_record_data = corresponding_highest[8:] 

                differences = {}
                for i, (non_highest_val, highest_val) in enumerate(zip(non_highest_data, highest_record_data)):
                    column_name = columns[i + 8] 

                    if non_highest_val == "N/A":
                        non_highest_val = 0
                    if highest_val == "N/A":
                        highest_val = 0

                    #print(f"Comparing column '{column_name}': {non_highest_val} vs {highest_val}")

                    if non_highest_val != highest_val:
                        differences[column_name] = (non_highest_val, highest_val)

                if differences:
                    cursor.execute(f"""
                        UPDATE {table_name} SET record_status = ? WHERE record_id = ?
                    """, ("Modified/Reused ID", non_highest_record_id)) 

                    #print(f"Updated record_id {non_highest_record_id} to 'Modified/Reused ID' due to differences.")

                else:
                    cursor.execute(f"""
                        UPDATE {table_name} SET record_status = ? WHERE record_id = ?
                    """, ("Duplicate (Active)", non_highest_record_id))

                    #print(f"Updated record_id {non_highest_record_id} to 'Duplicate (Active)' (no differences).")

    conn.commit()
    conn.close()
    print("[+] Record Classification Successfully Completed")