import datetime
import functools
import sqlite3
from flask import Flask, g, request, url_for, redirect, render_template, session, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash

# Database Location
DATABASE = 'library.db'

# Create the Flask App
app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY='dev'
)


def dict_factory(cursor, row):
    """
        Convert results gathered from DB into a dictionary rather
        than a tuple, as these are easier to process.
    """
    row_dict = {}
    for idx, col in enumerate(cursor.description):
        row_dict[col[0]] = row[idx]
    return row_dict


def get_db():
    """
        Create the connection to the SQLite DB and ensure
        that results come back as dictionaries.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        g._database.row_factory = dict_factory
    return db


@app.teardown_appcontext
def close_connection(exception):
    """
        When the flask app receives the request to shutdown, ensure
        that if a connection to the DB is active, that the connection
        is closed.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/home', methods=['GET'])
def show_all_books():
    """
        Gather a list of all books in the DB and display them to
        the user.
    """
    db = get_db()
    db_columns = "book_id, cover_url, title, summary, available_copies, author_id, name"
    get_books = db.execute(f"SELECT {db_columns} FROM books JOIN authors USING(author_id)").fetchall()
    return render_template('homepage.html',
                           title="Home",
                           book_list=get_books)


@app.route('/home/search', methods=['POST'])
def process_search():
    db = get_db()

    search_term = request.form.get('book')

    db_columns = "book_id, cover_url, title, summary, available_copies, author_id, name"
    books = db.execute(f"SELECT {db_columns} FROM books JOIN authors USING(author_id) WHERE title LIKE '%{search_term}%' OR name LIKE '%{search_term}%'").fetchall()
    return render_template('homepage.html',
                           title=search_term,
                           book_list=books)


@app.route('/book/<int:book_id>')
def show_book(book_id):
    """
        Gather all information on a specific book, this is specified
        via the book_id variable.
    """
    db = get_db()

    # Set all flags to false
    checked_out = False
    reserved = False
    favourited = False
    return_date = ""

    get_book = db.execute(f"SELECT * FROM books JOIN authors USING(author_id) WHERE book_id = {book_id}").fetchone()

    # Check if a user is logged in
    if g.user:
        # Set checked_out flag to true if the currently logged in user has this book
        check_out = db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND checked_out = ?",
                               (g.user['user_id'], book_id, True)).fetchone()
        if check_out is not None:
            checked_out = True
            # Get the remaining days as the difference between the return date and current date
            return_date = (
                    datetime.datetime.strptime(check_out['return_date'], '%Y-%m-%d') - datetime.datetime.now()).days

        # Set reserved flag to true if the currently logged in user has reserved this book
        if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND reserved = ?",
                      (g.user['user_id'], book_id, True)).fetchone() is not None:
            reserved = True

        # Set favourited flag to true if the currently logged in user has this book favourited
        if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND favourited = ?",
                      (g.user['user_id'], book_id, True)).fetchone() is not None:
            favourited = True

    return render_template('book.html',
                           title=get_book['title'],
                           book=get_book,
                           checked_out=checked_out,
                           reserved=reserved,
                           favourited=favourited,
                           return_date=return_date)


# This should only be accessed by admins - Add access_level to users table?
@app.route('/books/add', methods=['GET'])
def add_book_form():
    """
        Renders a form to the user so that they can add new
        books to the DB.
    """
    return '''
    <form action="/books/add" method="post" />
        cover url <input name="cover_url" type="text"/><br>
        title <input name="title" type="text"/><br>
        author <input name="author" type="text"/><br>
        genre <input name="genre" type="text"/><br>
        published date <input name="published_date" type="text"/><br>
        description <input name="description" type="text"/><br>
        shelf location <input name="shelf_location" type="text"/><br>
        total copies <input name="total_copies" type="text"/><br>
        available copies <input name="available_copies" type="text"/><br>
        <input value="Add Book" type="submit"/>
    </form>
    '''


@app.route('/books/add', methods=['POST'])
def add_book():
    """
        Once the add book form has been submitted add this book to the DB.
    """
    db = get_db()

    cover_url = request.form.get('cover_url')
    title = request.form.get('title')
    author_id = request.form.get('author')
    genre = request.form.get('genre')
    published_date = request.form.get('published_date')
    description = request.form.get('description')
    shelf_location = request.form.get('shelf_location')
    total_copies = request.form.get('total_copies')
    available_copies = request.form.get('available_copies')

    db_columns = "cover_url, title, author_id, genre, published_date, summary, shelf_location, " \
                 "total_copies, available_copies"

    db.execute(f"INSERT INTO books ({db_columns}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (cover_url, title, author_id, genre, published_date, description, shelf_location, total_copies,
                available_copies)).fetchone()
    db.commit()

    return redirect(url_for('show_books'))


@app.route('/auth', methods=['GET'])
def login_register():
    """
        Show the Login/Register page to the user so that they can
        Login/Register for the site.
    """
    return render_template("auth.html",
                           title="Login/Register")


@app.route('/auth/login', methods=['POST'])
def process_login():
    db = get_db()
    username = request.form.get('username')
    password = request.form.get('password')
    error = None

    user_data = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user_data is None:
        error = "Username is Incorrect!"
    elif not check_password_hash(user_data['password'], password):
        error = "Incorrect Password! Try Again!"

    if error is None:
        session.clear()
        session['user_id'] = user_data['user_id']
        flash('You were logged in successfully!', 'success')
        return redirect(url_for('show_all_books'))

    flash(error, 'error')
    return redirect(url_for('login_register'))


@app.route('/auth/register', methods=['POST'])
def process_register():
    db = get_db()
    full_name = request.form.get('full_name')
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    password_confirm = request.form.get('confirm_password')
    error = None

    required_fields = [full_name, username, email, password, password_confirm]

    for field in required_fields:
        if not field:
            error = "Please complete all fields!"

    if db.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone() is not None:
        error = f"User with the following username ({username}) already exists!"

    if password != password_confirm:
        error = "The two passwords you have entered do not match!"

    if error is None:
        db.execute("INSERT INTO users (full_name, username, email, password) VALUES (?, ?, ?, ?)",
                   (full_name, username, email, generate_password_hash(password)))
        db.commit()
        flash(f"{username} has been successfully created!", 'success')
        return redirect(url_for('login_register'))

    flash(error, 'error')
    return redirect(url_for('login_register'))


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE user_id = ?', (user_id,)
        ).fetchone()


@app.route('/logout')
def log_out():
    previous_msg = None

    # Get flashed message from previous URL
    if len(get_flashed_messages()) != 0:
        # Save message for use after clearing session
        previous_msg = get_flashed_messages()[0]

    session.clear()

    # Flash any messages
    if previous_msg is not None:
        flash(previous_msg, 'success')
    flash("Successfully Logged Out!", 'success')
    return redirect(url_for('show_all_books'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login_register'))
        return view(**kwargs)

    return wrapped_view


@app.route('/book/<int:book_id>/checkout/<int:user_id>', methods=['GET'])
@login_required
def check_out_book(user_id, book_id):
    """
        Check out the specified book using the user id of the logged in user.
    """
    db = get_db()

    delete = request.args.get('delete', default=False)

    # Get the number of available copies
    available_copies = \
        db.execute("SELECT available_copies FROM books WHERE book_id = ?", (book_id,)).fetchone()[
            'available_copies']

    if delete:
        db.execute("DELETE FROM user_books WHERE user_id = ? AND book_id = ? AND checked_out = ?",
                   (user_id, book_id, True))
        db.execute("UPDATE books SET available_copies = ? WHERE book_id = ?", (available_copies + 1, book_id))
        db.commit()

        flash("Successfully returned this book!", 'success')
        return redirect(request.referrer)
    else:
        # Check if user has this book checked out
        if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND checked_out = ?",
                      (user_id, book_id, True)).fetchone() is None:

            if available_copies > 0:
                # Check if a reserved book exists and remove it
                if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND reserved = ?",
                              (user_id, book_id, True)).fetchone() is not None:
                    db.execute("DELETE FROM user_books WHERE user_id = ? AND book_id = ? AND reserved = ?",
                               (user_id, book_id, True))

                # Get current date and date of return
                current_time = str(datetime.datetime.now()).split(".")[0]
                return_date = (datetime.datetime.today() + datetime.timedelta(days=7)).strftime('%Y-%m-%d')

                # Add the check_out book entry into user_books
                user_books_columns = "user_id, book_id, date_time, return_date, checked_out"
                db.execute(f"INSERT INTO user_books ({user_books_columns}) VALUES (?, ?, ?, ?, ?)",
                           (user_id, book_id, current_time, return_date, True))

                # Update the number of available copies
                db.execute("UPDATE books SET available_copies = ? WHERE book_id = ?", (available_copies - 1, book_id))
                db.commit()

                # Display message to user
                flash("You have successfully checked this book out!", 'success')
                return redirect(url_for('show_book', book_id=book_id))
            else:
                flash("There are no copies of this book available!", 'error')
                return redirect(request.referrer)


@app.route('/book/<int:book_id>/reserve/<int:user_id>', methods=['GET'])
@login_required
def reserve_book(user_id, book_id):
    """
        Reserve the specified book using the user id of the logged in user.
    """
    db = get_db()

    delete = request.args.get('delete', default=False)

    if delete:
        db.execute("DELETE FROM user_books WHERE user_id = ? AND book_id = ? AND reserved = ?",
                   (user_id, book_id, True))
        db.commit()

        flash("Successfully removed reservation of this book!", 'success')
        return redirect(request.referrer)
    else:
        # Check if the user has this book reserved
        if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND reserved = ?",
                      (user_id, book_id, True)).fetchone() is None:
            # Check if the user already has this book checked out
            checked_out = db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND checked_out = ?",
                                     (user_id, book_id, True)).fetchone()

            # Get the number of available copies
            available_copies = \
                db.execute("SELECT available_copies FROM books WHERE book_id = ?", (book_id,)).fetchone()[
                    'available_copies']

            # Only allow the user to reserve this book if there is no available copies
            # and they do not have this book checked out
            if available_copies == 0 and checked_out is None:
                user_books_columns = "user_id, book_id, date_time, reserved"
                current_time = str(datetime.datetime.now()).split(".")[0]

                # Update user_books to reserve this book for the current user
                db.execute(f"INSERT INTO user_books ({user_books_columns}) VALUES (?, ?, ?, ?)",
                           (user_id, book_id, current_time, True))
                db.commit()

                # Display message to user
                flash("You have successfully reserved this book!", 'success')
                return redirect(url_for('show_book', book_id=book_id))
            else:
                flash("This book cannot be reserved at this time!", 'error')
                return redirect(url_for('show_book', book_id=book_id))
        else:
            flash("You already have this book reserved!", 'error')
            return redirect(url_for('show_book', book_id=book_id))


@app.route('/book/<int:book_id>/favourite/<int:user_id>', methods=['GET'])
@login_required
def favourite_book(user_id, book_id):
    """
        Favourite the specified book for the currently logged in user
    """
    db = get_db()

    delete = request.args.get('delete', default=False)

    if delete:
        db.execute("DELETE FROM user_books WHERE user_id = ? AND book_id = ? AND favourited = ?",
                   (user_id, book_id, True))
        db.commit()

        flash("Successfully un-favourited this book!", "success")
        return redirect(request.referrer)
    else:
        # Check whether the user has this book favourited
        if db.execute("SELECT * FROM user_books WHERE user_id = ? AND book_id = ? AND favourited = ?",
                      (user_id, book_id, True)).fetchone() is None:

            # Add this book to the user's favourites by updating the DB
            user_books_columns = "user_id, book_id, favourited"
            db.execute(f"INSERT INTO user_books ({user_books_columns}) VALUES (?, ?, ?)",
                       (user_id, book_id, True))
            db.commit()

            # Display message to user
            flash("You have successfully favourited this book!", "success")
            return redirect(url_for('show_book', book_id=book_id))
        else:
            flash("You already have this book favourited!", "error")
            return redirect(url_for('show_book', book_id=book_id))


@app.route('/user/books')
@login_required
def user_books():
    """
        Shows the user information on their checked out books,
        reserved books & favourited books.
    """
    db = get_db()

    checked_out_columns = "book_id, return_date, cover_url, title, author_id, summary, name"

    # Gather all books the logged in user has checked out
    checked_out = db.execute(
        f"SELECT {checked_out_columns} FROM user_books JOIN books USING(book_id) JOIN authors USING(author_id) WHERE user_id = ? AND checked_out = ?",
        (g.user['user_id'], True)).fetchall()

    # Gather all books the logged in user has currently reserved
    reserved = db.execute(
        f"SELECT {checked_out_columns} FROM user_books JOIN books USING(book_id) JOIN authors USING(author_id) WHERE user_id = ? AND reserved = ?",
        (g.user['user_id'], True)).fetchall()

    # Gather all books the logged in user has favourited
    favourited = db.execute(
        f"SELECT {checked_out_columns} FROM user_books JOIN books USING(book_id) JOIN authors USING(author_id) WHERE user_id = ? AND favourited = ?",
        (g.user['user_id'], True)).fetchall()

    return render_template('my_books.html',
                           title='My Books',
                           checked_out=checked_out,
                           reserved=reserved,
                           favourited=favourited)


@app.route('/author/<int:author_id>')
def show_author(author_id):
    db = get_db()

    # Gather information on the specified author
    author_info = db.execute(f"SELECT * FROM authors WHERE author_id = ?", (author_id,)).fetchone()

    db_columns = "book_id, cover_url, title, summary, genre, published_date, name"

    # Gather all the books that are in the system that this author has wrote
    author_books = db.execute(f"SELECT {db_columns} FROM books JOIN authors USING(author_id) WHERE author_id = ?",
                              (author_id,)).fetchall()

    # Update the authors dictionary with information on how many books there are in this Library
    author_info.update({'total_books': len(author_books)})

    return render_template('authors.html',
                           title=author_info['name'],
                           author=author_info,
                           books=author_books)


@app.route('/user/profile')
@login_required
def user_profile():
    """
        Shows the user information on their checked out books,
        reserved books & favourited books.
    """

    return render_template('my_profile.html',
                           title=g.user['full_name'])


@app.route('/user/update', methods=['POST'])
@login_required
def process_update():
    """
        Update the users table based on new information entered
        into the profile page
    """
    db = get_db()
    process_type = request.form.get('process')

    # Check what the user would like to update
    if process_type == "picture":
        # Update the picture_url for the logged in user
        picture_url = request.form.get('user_picture')
        db.execute("UPDATE users SET picture_url = ? WHERE user_id = ?", (picture_url, g.user['user_id']))
        db.commit()
        flash("Profile Picture Successfully updated", 'success')
        return redirect(request.referrer)
    elif process_type == "details":
        # Update user details for the logged in user
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')

        # Check if any items need to be updated
        changed = False

        # Check if fields have data to update
        if full_name != g.user['full_name']:
            db.execute("UPDATE users SET full_name = ? WHERE user_id = ?", (full_name, g.user['user_id']))
            changed = True
        if username != g.user['username']:
            db.execute("UPDATE users SET username = ? WHERE user_id = ?", (username, g.user['user_id']))
            changed = True
        if email != g.user['email']:
            db.execute("UPDATE users SET email = ? WHERE user_id = ?", (email, g.user['user_id']))
            changed = True

        if changed:
            flash("User Details have been successfully updated!", "success")
            db.commit()
            return redirect(url_for('log_out'))
        else:
            flash("None of your details have been changed, try again!", "error")
            return redirect(request.referrer)
    elif process_type == "password":
        # Update the password for the current user
        current_password = request.form.get('current_password')
        new_pass = request.form.get('new_password')
        new_pass_confirm = request.form.get('new_password_conf')

        # Check current password is the same as password in db
        if check_password_hash(g.user['password'], current_password):
            # Check new password is not the same as current password
            if new_pass != current_password:
                # Check password confirm is the same as new password
                if new_pass == new_pass_confirm:
                    db.execute("UPDATE users SET password = ? WHERE user_id = ?",
                               (generate_password_hash(new_pass), g.user['user_id']))
                    db.commit()
                    flash("Password has been successfully changed!", "success")
                    return redirect(url_for('log_out'))
                else:
                    flash("Passwords do not match!", "error")
                    return redirect(request.referrer)
            else:
                flash("New password is the same as previous!", "error")
                return redirect(request.referrer)
        else:
            flash("Current password incorrect!", "error")
            return redirect(request.referrer)


@app.route('/')
def redirect_to_home():
    """
        If the user navigates to '/' redirect them to the homepage.
    """
    return redirect(url_for('show_all_books'))


if __name__ == '__main__':
    app.run(host='localhost', debug=True)
