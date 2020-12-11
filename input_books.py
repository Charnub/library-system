import csv
import sqlite3
import random

db = sqlite3.connect('library.db')

with open('books.csv', 'r', encoding="utf-8") as books:
    csv_reader = csv.reader(books, delimiter=',')

    author_names = []
    counter = 1
    for row in csv_reader:
        author = row[0]
        year = f"{row[1]}-01-01"
        title = row[2]
        image = row[3]

        blurb = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras purus est, tempor vel laoreet eget, aliquet nec elit. Ut dictum enim eget urna tincidunt, id varius tortor tristique. Praesent consectetur ac urna sit amet mollis. Sed dapibus quam in mi sollicitudin, et luctus sapien convallis. Pellentesque fringilla mauris lectus, nec scelerisque urna egestas vitae."
        summary = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."

        genre = ['Mystery', 'Sci-Fi', 'Thriller', 'Non-Fiction', 'Fantasy']

        shelf_prefix = random.randint(1, 10)
        shelf_ext = random.randint(100, 200)
        shelf = f"{shelf_prefix}.{shelf_ext}"

        total_copies = random.randint(5, 10)
        available_copies = total_copies - random.randint(0, 3)

        if author not in author_names:
            db.execute("INSERT INTO authors (name, dob, biography) VALUES (?, ?, ?)",
                       (author, year, summary))
            author_names.append(author)
            counter = counter + 1

        db.execute("INSERT INTO books (cover_url, title, author_id, genre, published_date, summary, blurb, shelf_location, total_copies, available_copies) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (image, title, counter, random.choice(genre), year, summary, blurb, shelf, total_copies, available_copies))

        db.commit()

    db.close()







