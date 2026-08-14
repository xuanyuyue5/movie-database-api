# Data

Large movie CSV files are not included in this repository.

The API import endpoint expects two local files:

- `movies.csv`
- `credits.csv`

Use Swagger UI or `POST /movies/import` to upload them after logging in as an admin user.

Generated SQLite databases and imported data stay local under `instance/` and are ignored by Git.
