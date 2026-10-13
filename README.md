# CoreWorks

Modularna IT platforma. Postojeći VELES ostaje zaseban projekat.

## Početni moduli

- **CoreWorks Hub** — portal, prijava korisnika, dashboard i administracija.
- **CoreWorks Monitor** — odvojena početna stranica; stvarni monitoring sledi kasnije.

## Lokalno pokretanje

```bash
./.venv/bin/python -m unittest discover -s tests -v
./.venv/bin/python -m coreworks.hub.cli
./.venv/bin/python run.py
```

Zatim otvori `http://127.0.0.1:5055`.

Prvi administratorski nalog pravi se interaktivno preko CLI komande. Lozinka se ne upisuje u fajl niti prikazuje na ekranu.

Aplikacija koristi lokalnu SQLite bazu `instance/coreworks.sqlite3`. Tajne su u `.env`, koji se ne commit-uje. U produkciji postavi `COREWORKS_COOKIE_SECURE=1` kada se koristi HTTPS, dodaj ograničavanje pokušaja prijave i konfiguraciju za produkcioni WSGI server.

Razvojni Flask server služi samo za lokalno testiranje i nije za javno izlaganje.
