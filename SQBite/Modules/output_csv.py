import csv

def clean_row(row):
    """
    Decodes byte strings with proper handling for BOM and invalid characters
    """
    cleaned_row = []
    for value in row:
        if isinstance(value, bytes):
            try:
                cleaned_row.append(value.decode("utf-8-sig").replace("\ufeff", "").replace("ï»¿", ""))
            except UnicodeDecodeError:
                cleaned_row.append(value.decode("utf-8", errors="replace"))
        else:
            cleaned_row.append(value)
    return cleaned_row

def write_to_csv(output_file, rows):
    """
    Writes extracted rows to a CSV file with dynamic column headers that adjust based on the row with the most columns.
    """
    if not rows:
        print("No data to write.")
        return

    # Determine the maximum number of columns across all rows
    max_columns = max(len(row) for row in rows)
    
    # Define base headers
    base_headers = ["Source File", "Page Number", "Table Name", "File Offset", "Row ID"]
    
    # Calculate additional columns 
    additional_columns = [f"Data_{i + 1}" for i in range(max_columns - len(base_headers))]
    
    # Combine headers
    column_headers = base_headers + additional_columns

    # Write to CSV
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile, escapechar='\\', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(column_headers)
        
        for row in rows:
            # Convert tuple to list and pad if necessary
            padded_row = list(row) + [''] * (max_columns - len(row))
            
            # Write the padded row with trimmed data if necessary
            writer.writerow(clean_row(padded_row[:max_columns]))
