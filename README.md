# Movie Database API

A Flask REST API for importing movie metadata, searching films, managing user playlists, and tracking API usage. The project uses Flask-RESTX for Swagger documentation, Flask-SQLAlchemy for persistence, and JWT tokens for role-based access control.

This is a cleaned portfolio version of the original backend project. Large datasets, local databases, virtual environments, IDE files, and course notebooks are intentionally excluded.

## Features

- JWT login with seeded admin and regular-user accounts
- Admin-only user management endpoints
- CSV import endpoint for `movies.csv` and `credits.csv`
- Movie list, detail, fuzzy title search, cast lookup, and crew lookup endpoints
- User playlist CRUD with owner/admin access control
- API usage logging for authenticated requests
- Usage export as CSV and usage chart output as PNG
- Swagger UI exposed by Flask-RESTX
- Integration tests covering authentication, access control, movie queries, playlists, and stats endpoints

## Repository Layout

```text
movie-database-api/
|-- app.py
|-- tests/
|   `-- test_api_integration.py
|-- data/
|   `-- README.md
|-- .env.example
|-- .gitignore
|-- README.md
`-- requirements.txt
```

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Copy the example environment file if you want to customize local settings:

```bash
copy .env.example .env
```

## Run

```bash
python app.py
```

The API starts on `http://127.0.0.1:5000` by default. Open the same URL in a browser to view the Swagger UI.

On first startup, the app creates the SQLite database and seeds two local development accounts:

```text
admin / admin
user  / user
```

For any non-local use, set stronger credentials through environment variables before starting the app.

## Import Movie Data

The original CSV files are not included in this repository. Use the admin account to log in, then call the import endpoint with local `movies.csv` and `credits.csv` files.

```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin\"}"
```

Use the returned token with Swagger UI or a multipart request to `POST /movies/import`.

## Tests

Start the API server first, then run:

```bash
pytest tests
```

The tests are integration tests against a running local server. They assume the default local accounts exist and, for movie/playlist tests, that movie data has been imported.

## Notes

- `instance/data.db` is generated locally and ignored by Git.
- The CSV datasets are intentionally excluded because they are large and can be obtained separately.
- `JWT_SECRET_KEY` should be changed for any environment beyond local development.
