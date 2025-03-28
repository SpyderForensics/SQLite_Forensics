def calculate_pointer_pages(auto_vacuum, page_size, total_pages):
    pointer_pages = []
    if auto_vacuum > 0:
        pointer_counter = 1
        pointer_entries = page_size // 5
        pointer_number = 0
        while pointer_number <= total_pages:
            pointer_number = ((pointer_entries * pointer_counter) + 2 + pointer_counter)
            if pointer_number > total_pages:
                break
            pointer_pages.append(pointer_number)
            pointer_counter += 1
    return pointer_pages