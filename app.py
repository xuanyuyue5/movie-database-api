import os
from zoneinfo import ZoneInfo

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import request
from flask_jwt_extended import create_access_token
from flask_restx import Namespace, Resource, fields
from werkzeug.security import check_password_hash
from datetime import timedelta
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret-change-me")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["RESTX_MASK_SWAGGER"] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

auth_schemes = {
    "Bearer": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "Enter: Bearer <your_token>"
    }
}

api = Api(
    app,
    version='1.0',
    title = 'Movie Database API',
    description = 'Movie search, playlist management, JWT authentication, and usage analytics API',
    authorizations=auth_schemes,
    security='Bearer',
)

LOCAL_TZ = ZoneInfo('Australia/Sydney')

DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")
DEFAULT_USER_USERNAME = os.getenv("DEFAULT_USER_USERNAME", "user")
DEFAULT_USER_PASSWORD = os.getenv("DEFAULT_USER_PASSWORD", "user")

#user

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)

    role = db.Column(db.String(30), default="user", nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(LOCAL_TZ),
        nullable=False
    )

    playlists = db.relationship(
        "Playlist",
        backref="owner",
        cascade="all, delete-orphan"
    )

    api_usages = db.relationship(
        "ApiUsage",
        backref="user",
        cascade="all, delete-orphan"
    )

#movie
class Movie(db.Model):
    __tablename__ = "movie"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(600))
    budget = db.Column(db.Float)

    genres = db.Column(db.Text)
    homepage = db.Column(db.Text)

    original_language = db.Column(db.String(40))
    original_title = db.Column(db.String(600))

    overview = db.Column(db.Text)
    popularity = db.Column(db.Float)

    production_companies = db.Column(db.Text)
    production_countries = db.Column(db.Text)

    release_date = db.Column(db.String(60))
    revenue = db.Column(db.Float)
    runtime = db.Column(db.Float)

    spoken_languages = db.Column(db.Text)
    status = db.Column(db.String(60))

    tagline = db.Column(db.Text)

    vote_average = db.Column(db.Float)
    vote_count = db.Column(db.Integer)

    keywords = db.Column(db.Text)

    cast_members = db.relationship(
        "CastMember",
        backref="movie",
        cascade="all, delete-orphan"
    )

    crew_members = db.relationship(
        "CrewMember",
        backref="movie",
        cascade="all, delete-orphan"
    )

#castmember
class CastMember(db.Model):
    __tablename__ = "cast_member"

    id = db.Column(db.Integer, primary_key=True)

    movie_id = db.Column(
        db.Integer,
        db.ForeignKey("movie.id"),
        nullable=False,
        index=True
    )

    person_id = db.Column(db.Integer, index=True)
    cast_id = db.Column(db.Integer)

    name = db.Column(db.String(350))
    character = db.Column(db.String(600))

    gender = db.Column(db.Integer)
    cast_order = db.Column("order", db.Integer)

    profile_path = db.Column(db.String(400))

#crewmember
class CrewMember(db.Model):
    __tablename__ = "crew_member"

    id = db.Column(db.Integer, primary_key=True)

    movie_id = db.Column(
        db.Integer,
        db.ForeignKey("movie.id"),
        nullable=False,
        index=True
    )

    person_id = db.Column(db.Integer, index=True)

    name = db.Column(db.String(350))
    department = db.Column(db.String(150))
    job = db.Column(db.String(150))

#playlist
class Playlist(db.Model):
    __tablename__ = "playlist"

    __table_args__ = (
        db.UniqueConstraint("user_id", "name"),
    )

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(250), nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(LOCAL_TZ),
        nullable=False
    )

    movies = db.relationship(
        "Movie",
        secondary="playlist_movies",
        backref="playlists"
    )

#playlistmovie
class PlaylistMovie(db.Model):
    __tablename__ = "playlist_movies"

    playlist_id = db.Column(
        db.Integer,
        db.ForeignKey("playlist.id"),
        primary_key=True
    )

    movie_id = db.Column(
        db.Integer,
        db.ForeignKey("movie.id"),
        primary_key=True
    )

#apiusage
class ApiUsage(db.Model):
    __tablename__ = "api_usage"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    endpoint = db.Column(db.String(600))
    method = db.Column(db.String(20))

    status_code = db.Column(db.Integer)

    timestamp = db.Column(
        db.DateTime,
        default=lambda: datetime.now(LOCAL_TZ)
    )

from werkzeug.security import generate_password_hash

import json
from functools import wraps
from flask import request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required


def safe_parse_json(raw):
    if not raw:
        return []
    try:
        return json.loads(raw)
    except Exception:
        return []


def get_current_user():
    uid = get_jwt_identity()
    if not uid:
        return None

    current = db.session.get(User, int(uid))
    if current and (current.is_active or current.role == "admin"):
        return current

    return None


def require_role(role=None):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def inner(*args, **kwargs):

            current = get_current_user()
            if not current:
                api.abort(403, "Invalid or inactive user")

            if role and current.role != role:
                api.abort(403, f"{role} role required")

            return fn(*args, **kwargs)

        return inner
    return wrapper


def build_usage_query(current, is_admin=False):
    stmt = db.select(ApiUsage)

    if is_admin:
        filter_uid = request.args.get("user_id", type=int)

        if filter_uid:
            stmt = stmt.filter_by(user_id=filter_uid)
        else:
            stmt = stmt.filter(ApiUsage.user_id != current.id)
    else:
        stmt = stmt.filter_by(user_id=current.id)

    return stmt

def seed_users():
    existing_admin = db.session.execute(
        db.select(User).filter_by(username=DEFAULT_ADMIN_USERNAME)
    ).scalar()

    if not existing_admin:
        db.session.add(User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            role="admin"
        ))

    existing_user = db.session.execute(
        db.select(User).filter_by(username=DEFAULT_USER_USERNAME)
    ).scalar()

    if not existing_user:
        db.session.add(User(
            username=DEFAULT_USER_USERNAME,
            password_hash=generate_password_hash(DEFAULT_USER_PASSWORD),
            role="user"
        ))

    db.session.commit()


from flask import request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from datetime import datetime


@app.after_request
def log_api_call(response):
    """Record API usage for authenticated users"""

    try:
        verify_jwt_in_request(optional=True)

        uid = get_jwt_identity()

        if uid:
            entry = ApiUsage(
                user_id=int(uid),
                endpoint=request.path,
                method=request.method,
                status_code=response.status_code,
                timestamp=datetime.now(LOCAL_TZ),
            )

            try:
                db.session.add(entry)
                db.session.commit()
            except:
                db.session.rollback()

    except Exception:
        pass

    return response

########################################## auth
auth_ns = Namespace(
    "auth",
    description="User authentication and management"
)
api.add_namespace(auth_ns)

login_body = auth_ns.model(
    "LoginInput",
    {
        "username": fields.String(required=True, description="Account username"),
        "password": fields.String(required=True, description="Account password"),
    },
)

token_resp = auth_ns.model(
    "TokenOutput",
    {
        "access_token": fields.String(description="JWT access token"),
    },
)


@auth_ns.route("/login")
class LoginAPI(Resource):

    @auth_ns.doc(
        summary="User login",
        description="Authenticate user and return JWT token"
    )
    @auth_ns.expect(login_body)
    @auth_ns.marshal_with(token_resp)
    @auth_ns.response(200, "Login success")
    @auth_ns.response(400, "Missing credentials")
    @auth_ns.response(401, "Wrong username or password")
    @auth_ns.response(403, "User disabled")
    def post(self):

        body = request.get_json() or {}

        uname = body.get("username")
        pwd = body.get("password")

        if not uname or not pwd:
            api.abort(400, "Username and password are required")

        matched = db.session.execute(
            db.select(User).filter_by(username=uname)
        ).scalar()

        if matched is None or not check_password_hash(matched.password_hash, pwd):
            api.abort(401, "Invalid username or password")

        if not matched.is_active:
            api.abort(403, "User account is inactive")

        token = create_access_token(
            identity=str(matched.id),
            additional_claims={
                "role": matched.role
            }
        )

        return {"access_token": token}, 200


account_model = auth_ns.model(
    "UserModel",
    {
        "id": fields.Integer,
        "username": fields.String,
        "role": fields.String,
        "is_active": fields.Boolean,
        "created_at": fields.DateTime(dt_format="iso8601"),
    },
)

account_list_model = auth_ns.model(
    "UserListModel",
    {
        "page": fields.Integer,
        "per_page": fields.Integer,
        "total": fields.Integer,
        "users": fields.List(fields.Nested(account_model)),
    },
)

toggle_active_model = auth_ns.model(
    "UpdateUser",
    {
        "is_active": fields.Boolean(required=True, description="Active status"),
    },
)

@auth_ns.route("/users")
class UserListAPI(Resource):

    @auth_ns.doc(
        summary="Get users",
        description="Admin only: get paginated users"
    )
    @auth_ns.param("page", "Page number", type=int)
    @auth_ns.param("per_page", "Items per page", type=int)
    @auth_ns.marshal_with(account_list_model)
    @auth_ns.response(200, "Success")
    @auth_ns.response(403, "Admin required")
    @require_role("admin")
    def get(self):

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        result = db.paginate(
            db.select(User),
            page=pg,
            per_page=pp,
            error_out=False
        )

        return {
            "page": result.page,
            "per_page": result.per_page,
            "total": result.total,
            "users": result.items,
        }, 200

    @auth_ns.doc(
        summary="Create user",
        description="Admin only: create a new user account"
    )
    @auth_ns.expect(login_body)
    @auth_ns.marshal_with(account_model, code=201)
    @auth_ns.response(201, "User created")
    @auth_ns.response(400, "Invalid input")
    @auth_ns.response(403, "Admin required")
    @auth_ns.response(409, "User already exists")
    @require_role("admin")
    def post(self):

        body = request.get_json() or {}
        uname = body.get("username")
        pwd = body.get("password")

        if not uname or not pwd:
            api.abort(400, "Username and password required")

        if len(uname) > 255:
            api.abort(400, "Username too long")

        duplicate = db.session.execute(
            db.select(User).filter_by(username=uname)
        ).scalar()

        if duplicate:
            api.abort(409, "Username already exists")

        new_account = User(
            username=uname,
            password_hash=generate_password_hash(pwd),
            role="user",
        )

        db.session.add(new_account)
        db.session.commit()

        return new_account, 201

@auth_ns.route("/users/<int:user_id>")
class UserDetailAPI(Resource):

    @auth_ns.doc(summary="Get user by id")
    @auth_ns.marshal_with(account_model)
    @auth_ns.response(404, "User not found")
    @require_role("admin")
    def get(self, user_id):

        target = db.session.get(User, user_id)

        if not target:
            api.abort(404, "User not found")

        return target, 200

    @auth_ns.doc(summary="Delete user")
    @auth_ns.response(404, "User not found")
    @auth_ns.response(400, "Cannot delete admin")
    @require_role("admin")
    def delete(self, user_id):

        target = db.session.get(User, user_id)

        if not target:
            api.abort(404, "User not found")

        if target.role == "admin":
            api.abort(400, "Cannot delete admin user")

        db.session.delete(target)
        db.session.commit()

        return {"message": "User deleted"}, 200

    @auth_ns.doc(summary="Activate or deactivate user")
    @auth_ns.expect(toggle_active_model)
    @auth_ns.marshal_with(account_model)
    @require_role("admin")
    def patch(self, user_id):

        target = db.session.get(User, user_id)

        if not target:
            api.abort(404, "User not found")

        body = request.get_json() or {}

        if "is_active" not in body:
            api.abort(400, "Missing is_active field")

        if target.role == "admin":
            return target, 200

        target.is_active = body["is_active"]
        db.session.commit()

        return target, 200

################################  movies
import pandas as pd

from flask import request
from flask_restx import Namespace, Resource, fields
from werkzeug.datastructures import FileStorage

from flask_jwt_extended import jwt_required

movies_ns = Namespace("movies", description="Movie data import and exploration")
api.add_namespace(movies_ns)
upload_parser = movies_ns.parser()

upload_parser.add_argument(
    "movies_file",
    location="files",
    type=FileStorage,
    required=True,
    help="Upload movie dataset"
)

upload_parser.add_argument(
    "credits_file",
    location="files",
    type=FileStorage,
    required=True,
    help="Upload credits dataset"
)

# Swagger response models
movie_item_model = movies_ns.model(
    "MovieItem",
    {
        "id": fields.Integer(description="Movie ID"),
        "title": fields.String(description="Movie title"),
    },
)

movie_list_model = movies_ns.model(
    "MovieListResult",
    {
        "page": fields.Integer,
        "per_page": fields.Integer,
        "total": fields.Integer,
        "movies": fields.List(fields.Nested(movie_item_model)),
    },
)

movie_detail_model = movies_ns.model(
    "MovieDetail",
    {
        "id": fields.Integer,
        "title": fields.String,
        "overview": fields.String,
        "release_date": fields.String,
        "vote_average": fields.Float,
    },
)

cast_member_model = movies_ns.model(
    "CastMemberItem",
    {
        "id": fields.Integer(description="Person ID"),
        "name": fields.String,
        "character": fields.String,
    },
)

movie_cast_model = movies_ns.model(
    "MovieCast",
    {
        "movie_id": fields.Integer,
        "cast": fields.List(fields.Nested(cast_member_model)),
    },
)

crew_member_model = movies_ns.model(
    "CrewMemberItem",
    {
        "id": fields.Integer(description="Person ID"),
        "name": fields.String,
        "job": fields.String,
    },
)

movie_crew_model = movies_ns.model(
    "MovieCrew",
    {
        "movie_id": fields.Integer,
        "crew": fields.List(fields.Nested(crew_member_model)),
    },
)

person_movies_model = movies_ns.model(
    "PersonMovies",
    {
        "person_id": fields.Integer,
        "page": fields.Integer,
        "per_page": fields.Integer,
        "total": fields.Integer,
        "movies": fields.List(fields.Nested(movie_item_model)),
    },
)

import_result_model = movies_ns.model(
    "ImportResult",
    {
        "message": fields.String,
        "movies": fields.Integer,
        "cast": fields.Integer,
        "crew": fields.Integer,
    },
)


@movies_ns.route("/import")
class MovieImportAPI(Resource):

    @movies_ns.doc(
        summary="Import movies and credits CSV",
        description="Admin only. Upload movies.csv and credits.csv. Re-importing replaces all existing data."
    )
    @movies_ns.expect(upload_parser)
    @movies_ns.marshal_with(import_result_model)
    @movies_ns.response(200, "Import completed")
    @movies_ns.response(400, "Invalid file format")
    @movies_ns.response(403, "Admin required")
    @require_role("admin")
    def post(self):

        args = upload_parser.parse_args()
        mfile = args.get("movies_file")
        cfile = args.get("credits_file")

        try:
            movies_df = pd.read_csv(mfile)
        except Exception as e:
            api.abort(400, f"Failed to read movies file: {e}")

        required_cols = ["id", "title"]
        if not all(col in movies_df.columns for col in required_cols):
            api.abort(400, "Invalid movies file format")

        try:
            credits_df = pd.read_csv(cfile)
        except Exception as e:
            api.abort(400, f"Failed to read credits file: {e}")

        movies_df = movies_df.where(movies_df.notna(), None)
        credits_df = credits_df.where(credits_df.notna(), None)

        # Clear all existing data to support re-import
        db.session.execute(db.delete(PlaylistMovie))
        db.session.execute(db.delete(CastMember))
        db.session.execute(db.delete(CrewMember))
        db.session.execute(db.delete(Movie))
        db.session.commit()

        n_movies = 0
        n_cast = 0
        n_crew = 0

        for _, row in movies_df.iterrows():

            mid = row.get("id")
            if not mid:
                continue

            rec = Movie(
                id=int(mid),
                title=row.get("title"),
                budget=row.get("budget"),
                genres=row.get("genres"),
                homepage=row.get("homepage"),
                original_language=row.get("original_language"),
                original_title=row.get("original_title"),
                overview=row.get("overview"),
                popularity=row.get("popularity"),
                production_companies=row.get("production_companies"),
                production_countries=row.get("production_countries"),
                release_date=row.get("release_date"),
                revenue=row.get("revenue"),
                runtime=row.get("runtime"),
                spoken_languages=row.get("spoken_languages"),
                status=row.get("status"),
                tagline=row.get("tagline"),
                vote_average=row.get("vote_average"),
                vote_count=row.get("vote_count"),
                keywords=row.get("keywords"),
            )

            db.session.add(rec)
            n_movies += 1

        for _, row in credits_df.iterrows():

            mid = row.get("id")
            if not mid:
                continue

            cast_list = safe_parse_json(row.get("cast"))
            crew_list = safe_parse_json(row.get("crew"))

            for c in cast_list:
                db.session.add(CastMember(
                    movie_id=int(mid),
                    person_id=c.get("id"),
                    name=c.get("name"),
                    character=c.get("character"),
                ))
                n_cast += 1

            for c in crew_list:
                db.session.add(CrewMember(
                    movie_id=int(mid),
                    person_id=c.get("id"),
                    name=c.get("name"),
                    department=c.get("department"),
                    job=c.get("job"),
                ))
                n_crew += 1

        db.session.commit()

        return {
            "message": "Import completed",
            "movies": n_movies,
            "cast": n_cast,
            "crew": n_crew,
        }, 200


from rapidfuzz import process, fuzz, utils as fuzz_utils

def fuzzy_match(query_str, choices):
    if not choices:
        return set()

    hits = process.extract(
        query_str,
        [name for name, _ in choices],
        scorer=fuzz.WRatio,
        processor=fuzz_utils.default_process,
        score_cutoff=60,
        limit=None,
    )

    return {choices[r[2]][1] for r in hits}


@movies_ns.route("")
class MovieListResource(Resource):

    @movies_ns.doc(
        summary="Search or list movies",
        description="Search movies by title, cast, or crew using fuzzy matching. Returns all movies when no filter is provided."
    )
    @movies_ns.param("title", "Movie title (fuzzy search)", type=str)
    @movies_ns.param("cast", "Cast member name (fuzzy search)", type=str)
    @movies_ns.param("crew", "Crew member name (fuzzy search)", type=str)
    @movies_ns.param("page", "Page number", type=int)
    @movies_ns.param("per_page", "Items per page", type=int)
    @movies_ns.marshal_with(movie_list_model)
    @movies_ns.response(200, "Success")
    def get(self):
        title_q = request.args.get("title")
        cast_q = request.args.get("cast")
        crew_q = request.args.get("crew")

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        # No filters: return all movies with database-level pagination
        if not title_q and not cast_q and not crew_q:
            paged = db.paginate(
                db.select(Movie).order_by(Movie.id),
                page=pg,
                per_page=pp,
                error_out=False,
            )
            return {
                "page": paged.page,
                "per_page": paged.per_page,
                "total": paged.total,
                "movies": [{"id": m.id, "title": m.title} for m in paged.items],
            }

        buckets = []

        if title_q:
            title_pairs = [(m.title, m.id) for m in db.session.scalars(db.select(Movie)) if m.title]
            buckets.append(fuzzy_match(title_q, title_pairs))

        if cast_q:
            cast_pairs = [(c.name, c.movie_id) for c in db.session.scalars(db.select(CastMember))]
            buckets.append(fuzzy_match(cast_q, cast_pairs))

        if crew_q:
            crew_pairs = [(c.name, c.movie_id) for c in db.session.scalars(db.select(CrewMember))]
            buckets.append(fuzzy_match(crew_q, crew_pairs))

        matched_ids = buckets[0]

        for s in buckets[1:]:
            matched_ids = matched_ids & s

        sorted_ids = sorted(matched_ids)
        total = len(sorted_ids)

        start = (pg - 1) * pp
        page_ids = sorted_ids[start:start + pp]

        movies = db.session.scalars(
            db.select(Movie)
            .filter(Movie.id.in_(page_ids))
            .order_by(Movie.id)
        ).all() if page_ids else []

        return {
            "page": pg,
            "per_page": pp,
            "total": total,
            "movies": [
                {
                    "id": m.id,
                    "title": m.title
                }
                for m in movies
            ]
        }


@movies_ns.route("/<int:movie_id>")
class MovieDetailResource(Resource):

    @movies_ns.doc(
        summary="Get movie details",
        description="Returns detailed information about a specific movie by ID."
    )
    @movies_ns.marshal_with(movie_detail_model)
    @movies_ns.response(200, "Success")
    @movies_ns.response(404, "Movie not found")
    def get(self, movie_id):

        rec = db.session.get(Movie, movie_id)

        if not rec:
            api.abort(404, "Movie not found")

        return {
            "id": rec.id,
            "title": rec.title,
            "overview": rec.overview,
            "release_date": rec.release_date,
            "vote_average": rec.vote_average
        }

@movies_ns.route("/<int:movie_id>/cast")
class MovieCastResource(Resource):

    @movies_ns.doc(
        summary="Get cast for a movie",
        description="Returns the full cast list for the specified movie."
    )
    @movies_ns.marshal_with(movie_cast_model)
    @movies_ns.response(200, "Success")
    @movies_ns.response(404, "Movie not found")
    def get(self, movie_id):

        rec = db.session.get(Movie, movie_id)
        if not rec:
            api.abort(404, "Movie not found")

        members = db.session.scalars(
            db.select(CastMember).filter_by(movie_id=movie_id)
        ).all()

        return {
            "movie_id": movie_id,
            "cast": [
                {
                    "id": c.person_id,
                    "name": c.name,
                    "character": c.character
                }
                for c in members
            ]
        }

@movies_ns.route("/<int:movie_id>/crew")
class MovieCrewResource(Resource):

    @movies_ns.doc(
        summary="Get crew for a movie",
        description="Returns the full crew list for the specified movie."
    )
    @movies_ns.marshal_with(movie_crew_model)
    @movies_ns.response(200, "Success")
    @movies_ns.response(404, "Movie not found")
    def get(self, movie_id):

        rec = db.session.get(Movie, movie_id)
        if not rec:
            api.abort(404, "Movie not found")

        members = db.session.scalars(
            db.select(CrewMember).filter_by(movie_id=movie_id)
        ).all()

        return {
            "movie_id": movie_id,
            "crew": [
                {
                    "id": c.person_id,
                    "name": c.name,
                    "job": c.job
                }
                for c in members
            ]
        }

@movies_ns.route("/cast/<int:person_id>")
class CastResource(Resource):

    @movies_ns.doc(
        summary="Get movies by cast member",
        description="Returns a paginated list of movies featuring the specified cast member."
    )
    @movies_ns.param("page", "Page number", type=int)
    @movies_ns.param("per_page", "Items per page", type=int)
    @movies_ns.marshal_with(person_movies_model)
    @movies_ns.response(200, "Success")
    @movies_ns.response(404, "Cast member not found")
    def get(self, person_id):

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        rows = db.session.scalars(
            db.select(CastMember).filter_by(person_id=person_id)
        ).all()

        if not rows:
            api.abort(404, "Cast member not found")

        mids = sorted(set(c.movie_id for c in rows))

        total = len(mids)
        start = (pg - 1) * pp
        page_ids = mids[start:start + pp]

        movies = db.session.scalars(
            db.select(Movie)
            .filter(Movie.id.in_(page_ids))
            .order_by(Movie.id)
        ).all() if page_ids else []

        return {
            "person_id": person_id,
            "page": pg,
            "per_page": pp,
            "total": total,
            "movies": [{"id": m.id, "title": m.title} for m in movies]
        }

@movies_ns.route("/crew/<int:person_id>")
class CrewResource(Resource):

    @movies_ns.doc(
        summary="Get movies by crew member",
        description="Returns a paginated list of movies involving the specified crew member."
    )
    @movies_ns.param("page", "Page number", type=int)
    @movies_ns.param("per_page", "Items per page", type=int)
    @movies_ns.marshal_with(person_movies_model)
    @movies_ns.response(200, "Success")
    @movies_ns.response(404, "Crew member not found")
    def get(self, person_id):

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        rows = db.session.scalars(
            db.select(CrewMember).filter_by(person_id=person_id)
        ).all()

        if not rows:
            api.abort(404, "Crew member not found")

        mids = sorted(set(c.movie_id for c in rows))

        total = len(mids)
        start = (pg - 1) * pp
        page_ids = mids[start:start + pp]

        movies = db.session.scalars(
            db.select(Movie)
            .filter(Movie.id.in_(page_ids))
            .order_by(Movie.id)
        ).all() if page_ids else []

        return {
            "person_id": person_id,
            "page": pg,
            "per_page": pp,
            "total": total,
            "movies": [{"id": m.id, "title": m.title} for m in movies]
        }

@movies_ns.route("/playlist/<int:playlist_id>")
class PlaylistResource(Resource):

    @movies_ns.doc(
        summary="Get movies in a playlist",
        description="Returns paginated movies in the specified playlist. Only accessible by the owner or admin."
    )
    @movies_ns.param("page", "Page number", type=int)
    @movies_ns.param("per_page", "Items per page", type=int)
    @movies_ns.response(200, "Success")
    @movies_ns.response(403, "Access denied")
    @movies_ns.response(404, "Playlist not found")
    @jwt_required()
    def get(self, playlist_id):

        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pl = db.session.get(Playlist, playlist_id)

        if not pl:
            api.abort(404, "Playlist not found")

        if caller.role != "admin" and pl.user_id != caller.id:
            api.abort(403, "Access denied")

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        mids = sorted(m.id for m in pl.movies)

        total = len(mids)
        start = (pg - 1) * pp
        page_ids = mids[start:start + pp]

        movies = db.session.scalars(
            db.select(Movie)
            .filter(Movie.id.in_(page_ids))
            .order_by(Movie.id)
        ).all() if page_ids else []

        return {
            "playlist_id": pl.id,
            "name": pl.name,
            "owner": pl.user_id,
            "page": pg,
            "per_page": pp,
            "total": total,
            "movies": [{"id": m.id, "title": m.title} for m in movies]
        }

#############################################  playlist
from flask_restx import Namespace, Resource
from flask_jwt_extended import jwt_required

playlists_ns = Namespace("playlists", description="User playlists")
api.add_namespace(playlists_ns)


def check_owner(pl, caller):
    if pl.user_id != caller.id:
        api.abort(403, "Access denied: not your playlist")


playlist_create_model = playlists_ns.model(
    "PlaylistCreate",
    {
        "name": fields.String(required=True, description="Playlist name"),
    },
)

playlist_create_response = playlists_ns.model(
    "PlaylistCreateResponse",
    {
        "id": fields.Integer,
        "name": fields.String,
    },
)

playlist_item_model = playlists_ns.model(
    "PlaylistItem",
    {
        "id": fields.Integer,
        "name": fields.String,
        "user_id": fields.Integer,
    },
)

playlist_list_model = playlists_ns.model(
    "PlaylistListResult",
    {
        "page": fields.Integer,
        "per_page": fields.Integer,
        "total": fields.Integer,
        "playlists": fields.List(fields.Nested(playlist_item_model)),
    },
)

playlist_detail_model = playlists_ns.model(
    "PlaylistDetail",
    {
        "id": fields.Integer,
        "name": fields.String,
        "movies": fields.List(fields.Integer, description="List of movie IDs"),
    },
)

playlist_message_model = playlists_ns.model(
    "PlaylistMessage",
    {"message": fields.String},
)


@playlists_ns.route("")
class PlaylistListResource(Resource):

    @playlists_ns.doc(
        summary="List user playlists",
        description="Returns a paginated list of all playlists owned by the authenticated user."
    )
    @playlists_ns.param("page", "Page number", type=int)
    @playlists_ns.param("per_page", "Items per page", type=int)
    @playlists_ns.marshal_with(playlist_list_model)
    @playlists_ns.response(200, "Success")
    @playlists_ns.response(401, "Missing or invalid token")
    @jwt_required()
    def get(self):
        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pg = request.args.get("page", 1, type=int)
        pp = request.args.get("per_page", 10, type=int)

        all_pls = db.session.scalars(
            db.select(Playlist)
            .filter_by(user_id=caller.id)
            .order_by(Playlist.id)
        ).all()

        total = len(all_pls)
        start = (pg - 1) * pp
        page_items = all_pls[start:start + pp]

        return {
            "page": pg,
            "per_page": pp,
            "total": total,
            "playlists": [
                {
                    "id": p.id,
                    "name": p.name,
                    "user_id": p.user_id
                }
                for p in page_items
            ]
        }

    @playlists_ns.doc(
        summary="Create a playlist",
        description="Creates a new private playlist for the authenticated user. Names must be unique per user."
    )
    @playlists_ns.expect(playlist_create_model)
    @playlists_ns.marshal_with(playlist_create_response, code=201)
    @playlists_ns.response(201, "Playlist created")
    @playlists_ns.response(400, "Missing playlist name")
    @playlists_ns.response(401, "Missing or invalid token")
    @playlists_ns.response(409, "Playlist name already exists")
    @jwt_required()
    def post(self):
        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        body = request.get_json() or {}
        pl_name = body.get("name")

        if not pl_name:
            api.abort(400, "Playlist name is required")

        duplicate = db.session.execute(
            db.select(Playlist).filter_by(user_id=caller.id, name=pl_name)
        ).scalar()

        if duplicate:
            api.abort(409, "Playlist name already exists")

        new_pl = Playlist(
            name=pl_name,
            user_id=caller.id
        )

        db.session.add(new_pl)
        db.session.commit()

        return {
            "id": new_pl.id,
            "name": new_pl.name
        }, 201


@playlists_ns.route("/<int:playlist_id>")
class PlaylistDetailResource(Resource):

    @playlists_ns.doc(
        summary="Get playlist details",
        description="Returns details and movie IDs for the specified playlist. Only accessible by the owner."
    )
    @playlists_ns.marshal_with(playlist_detail_model)
    @playlists_ns.response(200, "Success")
    @playlists_ns.response(401, "Missing or invalid token")
    @playlists_ns.response(403, "Access denied")
    @playlists_ns.response(404, "Playlist not found")
    @jwt_required()
    def get(self, playlist_id):
        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pl = db.session.get(Playlist, playlist_id)
        if not pl:
            api.abort(404, "Playlist not found")

        check_owner(pl, caller)

        return {
            "id": pl.id,
            "name": pl.name,
            "movies": [m.id for m in pl.movies]
        }

    @playlists_ns.doc(
        summary="Delete a playlist",
        description="Deletes the specified playlist. Only the owner can delete their playlist."
    )
    @playlists_ns.marshal_with(playlist_message_model)
    @playlists_ns.response(200, "Playlist deleted")
    @playlists_ns.response(401, "Missing or invalid token")
    @playlists_ns.response(403, "Access denied")
    @playlists_ns.response(404, "Playlist not found")
    @jwt_required()
    def delete(self, playlist_id):
        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pl = db.session.get(Playlist, playlist_id)
        if not pl:
            api.abort(404, "Playlist not found")

        check_owner(pl, caller)

        db.session.delete(pl)
        db.session.commit()

        return {"message": "Playlist deleted"}, 200


@playlists_ns.route("/<int:playlist_id>/movies/<int:movie_id>")
class PlaylistMovieResource(Resource):

    @playlists_ns.doc(
        summary="Add a movie to a playlist",
        description="Adds the specified movie to the playlist. Only the owner can modify their playlist."
    )
    @playlists_ns.marshal_with(playlist_message_model)
    @playlists_ns.response(200, "Movie added")
    @playlists_ns.response(401, "Missing or invalid token")
    @playlists_ns.response(403, "Access denied")
    @playlists_ns.response(404, "Playlist or movie not found")
    @playlists_ns.response(409, "Movie already in playlist")
    @jwt_required()
    def put(self, playlist_id, movie_id):

        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pl = db.session.get(Playlist, playlist_id)
        if not pl:
            api.abort(404, "Playlist not found")

        check_owner(pl, caller)

        film = db.session.get(Movie, movie_id)
        if not film:
            api.abort(404, "Movie not found")

        if film in pl.movies:
            api.abort(409, "Movie already exists in playlist")

        pl.movies.append(film)
        db.session.commit()

        return {"message": "Movie added"}, 200

    @playlists_ns.doc(
        summary="Remove a movie from a playlist",
        description="Removes the specified movie from the playlist. Only the owner can modify their playlist."
    )
    @playlists_ns.marshal_with(playlist_message_model)
    @playlists_ns.response(200, "Movie removed")
    @playlists_ns.response(401, "Missing or invalid token")
    @playlists_ns.response(403, "Access denied")
    @playlists_ns.response(404, "Playlist, movie, or movie not in playlist")
    @jwt_required()
    def delete(self, playlist_id, movie_id):

        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        pl = db.session.get(Playlist, playlist_id)
        if not pl:
            api.abort(404, "Playlist not found")

        check_owner(pl, caller)

        film = db.session.get(Movie, movie_id)
        if not film:
            api.abort(404, "Movie not found")

        if film not in pl.movies:
            api.abort(404, "Movie not in playlist")

        pl.movies.remove(film)
        db.session.commit()

        return {"message": "Movie removed"}, 200

#############################      stats
import csv
import io
import re
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from flask import Response, send_file

stats_ns = Namespace("stats", description="API usage statistics")
api.add_namespace(stats_ns)


def normalize_path(path: str):
    return re.sub(r"/\d+", "/{id}", path)


@stats_ns.route("/usage/csv")
class StatsCSVResource(Resource):

    @stats_ns.doc(
        summary="Download usage statistics as CSV",
        description=(
            "Returns API usage records as a downloadable CSV file. "
            "Regular users see only their own activity. "
            "Admin sees all users' activity excluding their own. "
            "Admin can filter by user_id query parameter."
        )
    )
    @stats_ns.param("user_id", "Admin only: filter by specific user ID", type=int)
    @stats_ns.response(200, "CSV file returned")
    @stats_ns.response(401, "Missing or invalid token")
    @stats_ns.response(403, "Invalid or inactive user")
    @jwt_required()
    def get(self):

        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        is_admin = caller.role == "admin"

        stmt = build_usage_query(caller, is_admin)
        records = db.session.scalars(
            stmt.order_by(ApiUsage.timestamp.desc())
        ).all()

        uid_set = {r.user_id for r in records}
        uname_map = {
            u.id: u.username
            for u in db.session.scalars(
                db.select(User).filter(User.id.in_(uid_set))
            ).all()
        }

        buf = io.StringIO()
        writer = csv.writer(buf)

        writer.writerow([
            "timestamp",
            "user_id",
            "username",
            "endpoint",
            "method",
            "status_code"
        ])

        for r in records:
            writer.writerow([
                r.timestamp.isoformat() if r.timestamp else "",
                r.user_id,
                uname_map.get(r.user_id, "unknown"),
                r.endpoint,
                r.method,
                r.status_code
            ])

        buf.seek(0)

        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=usage.csv"
            }
        )


@stats_ns.route("/usage/chart")
class StatsChartResource(Resource):

    @stats_ns.doc(
        summary="View usage statistics as a chart",
        description=(
            "Returns a PNG image with two charts: "
            "(1) daily API request volume (line chart) and "
            "(2) top 10 most-used endpoints (bar chart). "
            "Regular users see only their own activity. "
            "Admin sees all users' activity excluding their own."
        )
    )
    @stats_ns.response(200, "PNG image returned")
    @stats_ns.response(401, "Missing or invalid token")
    @stats_ns.response(403, "Invalid or inactive user")
    @jwt_required()
    def get(self):

        caller = get_current_user()
        if not caller:
            api.abort(403, "Invalid user")

        is_admin = caller.role == "admin"

        stmt = build_usage_query(caller, is_admin)
        records = db.session.scalars(stmt).all()

        if not records:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.text(0.5, 0.5, "No Data", ha="center", va="center",
                    transform=ax.transAxes)
            ax.axis("off")
            out = io.BytesIO()
            fig.savefig(out, format="png")
            plt.close(fig)
            out.seek(0)
            return send_file(out, mimetype="image/png")

        rows = []
        for r in records:
            rows.append({
                "date": r.timestamp.date() if r.timestamp else None,
                "endpoint": normalize_path(r.endpoint),
                "method": r.method
            })

        df = pd.DataFrame(rows)

        # Two charts side by side: daily requests + top endpoints
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

        daily = df.groupby("date").size()
        daily.plot(kind="line", ax=ax1, marker="o")
        ax1.set_title("Daily API Requests")
        ax1.set_xlabel("Date")
        ax1.set_ylabel("Requests")
        ax1.tick_params(axis="x", rotation=30)

        top_eps = df["endpoint"].value_counts().head(10)
        top_eps.plot(kind="bar", ax=ax2)
        ax2.set_title("Top API Endpoints Usage")
        ax2.set_xlabel("Endpoint")
        ax2.set_ylabel("Requests")
        ax2.tick_params(axis="x", rotation=45)
        for lbl in ax2.get_xticklabels():
            lbl.set_ha("right")

        plt.tight_layout()

        out = io.BytesIO()
        fig.savefig(out, format="png", bbox_inches="tight")
        plt.close(fig)
        out.seek(0)

        return send_file(
            out,
            mimetype="image/png",
            as_attachment=False
        )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_users()

    app.run(
        host=os.getenv("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )
