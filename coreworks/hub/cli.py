import getpass
import os
import re

from werkzeug.security import generate_password_hash

from coreworks.hub import create_app


def main():
    app = create_app()
    username = input("Novo administratorsko korisničko ime: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        raise SystemExit("Ime mora imati 3–40 znakova: slova, brojevi, _ . -")

    password = getpass.getpass("Administratorska lozinka (min. 14 znakova): ")
    confirm = getpass.getpass("Ponovi lozinku: ")
    if len(password) < 14:
        raise SystemExit("Lozinka mora imati najmanje 14 znakova.")
    if password != confirm:
        raise SystemExit("Lozinke se ne poklapaju.")

    with app.app_context():
        db = __import__("flask").current_app
        from flask import g
        # Koristi istu SQLite bazu koju koristi aplikacija.
        import sqlite3
        conn = sqlite3.connect(app.config["DATABASE"])
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (?, ?, 'admin')",
                (username, generate_password_hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise SystemExit("Taj korisnik već postoji.")
        finally:
            conn.close()

    print("Administratorski nalog je kreiran.")


if __name__ == "__main__":
    main()
