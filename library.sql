-- Create Tables

CREATE TABLE users (
    user_id integer primary key autoincrement not null,
    full_name varchar(100),
    username varchar(25),
    email varchar(255),
    password varchar(50),
    picture_url varchar(255)
);

CREATE TABLE authors (
    author_id integer primary key autoincrement not null,
    name varchar(100),
    dob integer,
    biography varchar(255)
);

CREATE TABLE books (
    book_id integer primary key autoincrement not null,
    cover_url varchar(255),
    title varchar(255),
    author_id integer,
    genre varchar(50),
    published_date date,
    summary varchar(255),
    blurb text,
    shelf_location varchar(255),
    total_copies integer,
    available_copies integer,
    FOREIGN KEY (author_id) REFERENCES authors(author_id)
);

CREATE TABLE user_books (
    user_book_id integer primary key autoincrement not null,
    user_id integer,
    book_id integer,
    date_time datetime,
    reserved boolean,
    checked_out boolean,
    favourited boolean,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (book_id) REFERENCES books(book_id)
);

-- View Table Info

SELECT * FROM users;

SELECT * FROM authors;

SELECT * FROM books;

SELECT * FROM user_books;

-- Insert Statements

INSERT INTO users (full_name, username, email, password, picture_url)
VALUES ('Charlie Parsons', 'cparsons', 'charlie.parsons@altran.com', 'password', 'https://secure.gravatar.com/avatar/9b6c8912d7388cd214220ad3ce1ba977')

INSERT INTO authors (name, dob, biography) VALUES ('J.K. Rowling', '1970-03-17', 'Wrote Harry Potter!')

INSERT INTO books (cover_url, title, author_id, genre, published_date, summary, shelf_location, total_copies, available_copies)
VALUES ('https://upload.wikimedia.org/wikipedia/en/6/6b/Harry_Potter_and_the_Philosopher%27s_Stone_Book_Cover.jpg', 'Harry Potter and the Philosophers Stone', 1, 'Fantasy', '1997-06-26', 'Its about a stone!', '8B.106', 2, 1)

INSERT INTO user_books (user_id, book_id, date_time, reserved, checked_out, favourited)
VALUES (1, 1, datetime(), False, True, False)

-- Join Queries

SELECT title, name FROM books JOIN authors USING(author_id)

SELECT full_name, title FROM user_books
JOIN books USING(book_id)
JOIN users USING(user_id)

-- Drop Tables

DROP TABLE users;
DROP TABLE authors;
DROP TABLE books;
DROP TABLE user_books;