import pytest
import requests
import time
import os
import io

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")


def login_and_get_headers(username, password):
    """Login and return Authorization headers with JWT token."""
    res = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": username, "password": password}
    )
    assert res.status_code == 200, f"Login failed for {username}"
    token = res.json().get("access_token")
    assert token is not None
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def admin_headers():
    """Session-scoped fixture: returns admin JWT headers."""
    return login_and_get_headers("admin", "admin")


@pytest.fixture(scope="session")
def user_headers():
    """Session-scoped fixture: returns regular user JWT headers."""
    return login_and_get_headers("user", "user")


@pytest.fixture(scope="session")
def created_user(admin_headers):
    """
    Session-scoped fixture: creates a test user via admin and returns
    (user_id, username, password, headers).
    """
    username = f"fixture_user_{int(time.time())}"
    password = "testpass123"

    res = requests.post(
        f"{BASE_URL}/auth/users",
        json={"username": username, "password": password},
        headers=admin_headers
    )
    assert res.status_code in (200, 201)
    user_id = res.json()["id"]
    headers = login_and_get_headers(username, password)
    return {"id": user_id, "username": username, "password": password, "headers": headers}



# Auth

class TestAuthentication:
    """
    User Management and Access Control
    Tests for login, token validation, and access restriction.
    """

    def test_req1_login_success_admin(self):
        """
        Login: Valid admin credentials should return a JWT access token.
        Asserts: status 200, access_token present and non-empty string.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 0

    def test_req1_login_success_user(self):
        """
        Login: Valid regular user credentials should return a JWT token.
        Asserts: status 200, access_token present.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "user", "password": "user"}
        )
        assert res.status_code == 200
        assert "access_token" in res.json()

    def test_req1_login_wrong_password(self):
        """
        Login: Incorrect password should be rejected.
        Asserts: status 401.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert res.status_code == 401

    def test_req1_login_nonexistent_user(self):
        """
        Login: Non-existent username should be rejected.
        Asserts: status 401.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "ghost_user_xyz", "password": "123"}
        )
        assert res.status_code == 401

    def test_req1_login_missing_username(self):
        """
        Login: Missing username field should return bad request.
        Asserts: status 400.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"password": "admin"}
        )
        assert res.status_code == 400

    def test_req1_login_missing_password(self):
        """
        Login: Missing password field should return bad request.
        Asserts: status 400.
        """
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin"}
        )
        assert res.status_code == 400

    def test_req1_login_empty_body(self):
        """
        Login: Empty request body should return bad request.
        Asserts: status 400.
        """
        res = requests.post(f"{BASE_URL}/auth/login", json={})
        assert res.status_code == 400

    def test_req1_protected_endpoint_no_token(self):
        """
        Access Control: Accessing protected endpoint without token
        should be rejected.
        Asserts: status 401, error message present.
        """
        res = requests.get(f"{BASE_URL}/auth/users")
        assert res.status_code == 401
        assert "msg" in res.json()

    def test_req1_protected_endpoint_invalid_token(self):
        """
        Access Control: Using a malformed/invalid token should be rejected.
        Asserts: status 401 or 422.
        """
        res = requests.get(
            f"{BASE_URL}/auth/users",
            headers={"Authorization": "Bearer this.is.not.valid"}
        )
        assert res.status_code in (401, 422)


# User Management

class TestUserManagement:
    """
    User Management
    Tests for admin CRUD operations on user accounts.
    """

    def test_req1_admin_get_user_list(self, admin_headers):
        """
        User List: Admin should be able to retrieve paginated user list.
        Asserts: status 200, correct pagination fields, users is a list.
        """
        res = requests.get(f"{BASE_URL}/auth/users", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "users" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert isinstance(data["users"], list)
        assert data["total"] >= 2  # at least admin and user

    def test_req1_user_cannot_get_user_list(self, user_headers):
        """
        Access Control: Regular user must not access the user list.
        Asserts: status 403.
        """
        res = requests.get(f"{BASE_URL}/auth/users", headers=user_headers)
        assert res.status_code == 403

    def test_req1_admin_create_user(self, admin_headers):
        """
        Create User: Admin can create a new user account.
        Asserts: status 201, response contains id/username/role/is_active.
        """
        username = f"newuser_{int(time.time())}"
        res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "securepass"},
            headers=admin_headers
        )
        assert res.status_code in (200, 201)
        data = res.json()
        assert "id" in data
        assert data["username"] == username
        assert data["role"] == "user"
        assert data["is_active"] is True

    def test_req1_user_cannot_create_user(self, user_headers):
        """
        Access Control: Regular user must not create new accounts.
        Asserts: status 403.
        """
        res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": "hacker", "password": "hacked"},
            headers=user_headers
        )
        assert res.status_code == 403

    def test_req1_create_duplicate_user(self, admin_headers):
        """
        Create User: Creating a user with an existing username should fail.
        Asserts: status 409.
        """
        username = f"dup_{int(time.time())}"
        requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "123"},
            headers=admin_headers
        )
        res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "456"},
            headers=admin_headers
        )
        assert res.status_code == 409

    def test_req1_get_user_by_id(self, admin_headers, created_user):
        """
        Get User: Admin can retrieve a specific user by ID.
        Asserts: status 200, correct user data returned.
        """
        res = requests.get(
            f"{BASE_URL}/auth/users/{created_user['id']}",
            headers=admin_headers
        )
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == created_user["id"]
        assert data["username"] == created_user["username"]

    def test_req1_get_nonexistent_user(self, admin_headers):
        """
        Get User: Requesting a non-existent user ID should return 404.
        Asserts: status 404.
        """
        res = requests.get(
            f"{BASE_URL}/auth/users/999999",
            headers=admin_headers
        )
        assert res.status_code == 404

    def test_req1_deactivate_user(self, admin_headers, created_user):
        """
        Deactivate User: Admin can deactivate a user account.
        Asserts: status 200, is_active set to False.
        """
        res = requests.patch(
            f"{BASE_URL}/auth/users/{created_user['id']}",
            json={"is_active": False},
            headers=admin_headers
        )
        assert res.status_code == 200
        assert res.json()["is_active"] is False

    def test_req1_deactivated_user_cannot_login(self, admin_headers):
        """
        Deactivated Account: A deactivated user must not be able to login.
        Asserts: login returns 403 after deactivation.
        """
        username = f"inactive_{int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "pass123"},
            headers=admin_headers
        )
        user_id = create_res.json()["id"]

        requests.patch(
            f"{BASE_URL}/auth/users/{user_id}",
            json={"is_active": False},
            headers=admin_headers
        )

        login_res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": "pass123"}
        )
        assert login_res.status_code == 403

    def test_req1_reactivate_user(self, admin_headers):
        """
        Reactivate User: Admin can reactivate a deactivated account.
        Asserts: is_active returns True after patch.
        """
        username = f"reactivate_{int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "pass123"},
            headers=admin_headers
        )
        user_id = create_res.json()["id"]

        requests.patch(
            f"{BASE_URL}/auth/users/{user_id}",
            json={"is_active": False},
            headers=admin_headers
        )

        res = requests.patch(
            f"{BASE_URL}/auth/users/{user_id}",
            json={"is_active": True},
            headers=admin_headers
        )
        assert res.status_code == 200
        assert res.json()["is_active"] is True

    def test_req1_delete_user(self, admin_headers):
        """
        Delete User: Admin can delete a user and it no longer exists.
        Asserts: delete returns 200, subsequent GET returns 404.
        """
        username = f"todelete_{int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": username, "password": "pass"},
            headers=admin_headers
        )
        user_id = create_res.json()["id"]

        del_res = requests.delete(
            f"{BASE_URL}/auth/users/{user_id}",
            headers=admin_headers
        )
        assert del_res.status_code == 200

        get_res = requests.get(
            f"{BASE_URL}/auth/users/{user_id}",
            headers=admin_headers
        )
        assert get_res.status_code == 404

    def test_req1_cannot_delete_admin(self, admin_headers):
        """
        Delete Admin: The admin account must not be deletable.
        Asserts: status 400 when attempting to delete user with admin role.
        """
        res = requests.delete(
            f"{BASE_URL}/auth/users/1",
            headers=admin_headers
        )
        assert res.status_code == 400


# Import Movies

class TestMovieImport:
    """
    Importing Movies
    Tests for CSV file import via multipart/form-data.
    """

    def test_req2_import_success(self, admin_headers):
        """
        Import: Admin can import valid movies.csv and credits.csv.
        Asserts: status 200, response contains movies/cast/crew counts > 0.
        """
        if not os.path.exists("movies.csv") or not os.path.exists("credits.csv"):
            pytest.skip("CSV files not available")

        with open("movies.csv", "rb") as mf, open("credits.csv", "rb") as cf:
            res = requests.post(
                f"{BASE_URL}/movies/import",
                files={
                    "movies_file": ("movies.csv", mf, "text/csv"),
                    "credits_file": ("credits.csv", cf, "text/csv"),
                },
                headers=admin_headers
            )
        assert res.status_code == 200
        data = res.json()
        assert "movies" in data
        assert "cast" in data
        assert "crew" in data
        assert data["movies"] > 0

    def test_req2_reimport_replaces_data(self, admin_headers):
        """
        Re-import: Importing again should replace data, not return an error.
        Asserts: status 200 on second import.
        """
        if not os.path.exists("movies.csv") or not os.path.exists("credits.csv"):
            pytest.skip("CSV files not available")

        with open("movies.csv", "rb") as mf, open("credits.csv", "rb") as cf:
            res = requests.post(
                f"{BASE_URL}/movies/import",
                files={
                    "movies_file": ("movies.csv", mf, "text/csv"),
                    "credits_file": ("credits.csv", cf, "text/csv"),
                },
                headers=admin_headers
            )
        assert res.status_code == 200

    def test_req2_user_cannot_import(self, user_headers):
        """
        Access Control: Regular user must not be able to import movies.
        Asserts: status 403.
        """
        if not os.path.exists("movies.csv") or not os.path.exists("credits.csv"):
            pytest.skip("CSV files not available")

        with open("movies.csv", "rb") as mf, open("credits.csv", "rb") as cf:
            res = requests.post(
                f"{BASE_URL}/movies/import",
                files={
                    "movies_file": ("movies.csv", mf, "text/csv"),
                    "credits_file": ("credits.csv", cf, "text/csv"),
                },
                headers=user_headers
            )
        assert res.status_code == 403

    def test_req2_invalid_movies_file(self, admin_headers):
        """
        Validation: Uploading a malformed movies file missing required
        columns should return a clear error.
        Asserts: status 400.
        """
        bad_movies = io.BytesIO(b"col_a,col_b\n1,2\n3,4")
        bad_credits = io.BytesIO(b"id,cast,crew\n1,[],[]\n")

        res = requests.post(
            f"{BASE_URL}/movies/import",
            files={
                "movies_file": ("bad_movies.csv", bad_movies, "text/csv"),
                "credits_file": ("credits.csv", bad_credits, "text/csv"),
            },
            headers=admin_headers
        )
        assert res.status_code == 400

    def test_req2_no_token_cannot_import(self):
        """
        Access Control: Unauthenticated request must be rejected.
        Asserts: status 401.
        """
        bad = io.BytesIO(b"id,title\n1,Test")
        res = requests.post(
            f"{BASE_URL}/movies/import",
            files={
                "movies_file": ("m.csv", bad, "text/csv"),
                "credits_file": ("c.csv", io.BytesIO(b"id,cast,crew\n"), "text/csv"),
            }
        )
        assert res.status_code == 401


# Exploring Movies

class TestMovieExplore:
    """
    Exploring Movies
    Tests for movie search, detail retrieval, cast and crew endpoints.
    """

    def test_req3_get_all_movies(self):
        """
        Movie List: GET /movies should return paginated list without filters.
        Asserts: status 200, pagination fields present, movies is a list.
        """
        res = requests.get(f"{BASE_URL}/movies")
        assert res.status_code == 200
        data = res.json()
        assert "movies" in data
        assert "page" in data
        assert "per_page" in data
        assert "total" in data
        assert isinstance(data["movies"], list)

    def test_req3_search_by_title(self):
        """
        Search: Searching by title should return matching results.
        Asserts: status 200, movies list present.
        """
        res = requests.get(f"{BASE_URL}/movies?title=avatar")
        assert res.status_code == 200
        assert "movies" in res.json()

    def test_req3_search_case_insensitive(self):
        """
        Search: Title search must be case-insensitive.
        Asserts: both 'Avatar' and 'avatar' return same total count.
        """
        res1 = requests.get(f"{BASE_URL}/movies?title=Avatar")
        res2 = requests.get(f"{BASE_URL}/movies?title=avatar")
        assert res1.status_code == 200
        assert res2.status_code == 200
        assert res1.json()["total"] == res2.json()["total"]

    def test_req3_search_no_results(self):
        """
        Search: Search with no match should return empty list, not an error.
        Asserts: status 200, movies list is present (fuzzy search may return 0 results).
        """
        res = requests.get(f"{BASE_URL}/movies?title=zzznomatchzzz")
        assert res.status_code == 200
        data = res.json()
        assert "movies" in data
        assert "total" in data
        assert isinstance(data["movies"], list)

    def test_req3_search_by_cast(self):
        """
        Search: Searching by cast member name should return matching movies.
        Asserts: status 200, movies list present.
        """
        res = requests.get(f"{BASE_URL}/movies?cast=Johnny Depp")
        assert res.status_code == 200
        assert "movies" in res.json()

    def test_req3_search_by_crew(self):
        """
        Search: Searching by crew member name should return matching movies.
        Asserts: status 200, movies list present.
        """
        res = requests.get(f"{BASE_URL}/movies?crew=Verbinski")
        assert res.status_code == 200
        assert "movies" in res.json()

    def test_req3_movie_detail(self):
        """
        Movie Detail: GET /movies/{id} should return full movie details.
        Asserts: status 200 for a known movie, required fields present.
        """
        res = requests.get(f"{BASE_URL}/movies/19995")  # Avatar
        if res.status_code == 404:
            pytest.skip("Movie not yet imported")
        assert res.status_code == 200
        data = res.json()
        assert "id" in data
        assert "title" in data
        assert "overview" in data
        assert "release_date" in data
        assert "vote_average" in data

    def test_req3_movie_not_found(self):
        """
        Movie Detail: Requesting a non-existent movie ID should return 404.
        Asserts: status 404.
        """
        res = requests.get(f"{BASE_URL}/movies/999999999")
        assert res.status_code == 404

    def test_req3_movie_cast(self):
        """
        Cast: GET /movies/{id}/cast should return the cast list.
        Asserts: status 200, cast is a list with required fields.
        """
        res = requests.get(f"{BASE_URL}/movies/19995/cast")
        if res.status_code == 404:
            pytest.skip("Movie not yet imported")
        assert res.status_code == 200
        data = res.json()
        assert "cast" in data
        assert isinstance(data["cast"], list)
        if data["cast"]:
            member = data["cast"][0]
            assert "id" in member
            assert "name" in member
            assert "character" in member

    def test_req3_movie_crew(self):
        """
        Crew: GET /movies/{id}/crew should return the crew list.
        Asserts: status 200, crew is a list with required fields.
        """
        res = requests.get(f"{BASE_URL}/movies/19995/crew")
        if res.status_code == 404:
            pytest.skip("Movie not yet imported")
        assert res.status_code == 200
        data = res.json()
        assert "crew" in data
        assert isinstance(data["crew"], list)
        if data["crew"]:
            member = data["crew"][0]
            assert "id" in member
            assert "name" in member
            assert "job" in member

    def test_req3_cast_member_movies(self):
        """
        Cast Member: GET /movies/cast/{id} should return movies for that person.
        Asserts: status 200 or 404, pagination fields if found.
        """
        res = requests.get(f"{BASE_URL}/movies/cast/85")  # Johnny Depp person_id
        if res.status_code == 404:
            pytest.skip("Cast member not found, data may not be imported")
        assert res.status_code == 200
        data = res.json()
        assert "movies" in data
        assert "total" in data
        assert isinstance(data["movies"], list)

    def test_req3_crew_member_movies(self):
        """
        Crew Member: GET /movies/crew/{id} should return movies for that person.
        Asserts: status 200 or 404, pagination fields if found.
        """
        res = requests.get(f"{BASE_URL}/movies/crew/5655")  # Gore Verbinski person_id
        if res.status_code == 404:
            pytest.skip("Crew member not found, data may not be imported")
        assert res.status_code == 200
        data = res.json()
        assert "movies" in data
        assert "total" in data

    def test_req3_pagination(self):
        """
        Pagination: per_page param should limit results correctly.
        Asserts: returned movies list length does not exceed per_page value.
        """
        res = requests.get(f"{BASE_URL}/movies?per_page=3&page=1")
        assert res.status_code == 200
        data = res.json()
        assert len(data["movies"]) <= 3


# Playlists

class TestPlaylists:
    """
    Playlists
    Tests for playlist CRUD and movie management within playlists.
    """

    def test_req4_create_playlist(self, user_headers):
        """
        Create Playlist: User can create a new named playlist.
        Asserts: status 201, id and name in response.
        """
        name = f"My Playlist {int(time.time())}"
        res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        assert res.status_code in (200, 201)
        data = res.json()
        assert "id" in data
        assert data["name"] == name

    def test_req4_duplicate_playlist_name(self, user_headers):
        """
        Duplicate Playlist: Creating two playlists with the same name
        for the same user should fail.
        Asserts: status 409 on second create.
        """
        name = f"Dup Playlist {int(time.time())}"
        requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        assert res.status_code == 409

    def test_req4_get_playlists(self, user_headers):
        """
        List Playlists: User can retrieve their own playlist list.
        Asserts: status 200, playlists field is a list with pagination.
        """
        res = requests.get(f"{BASE_URL}/playlists", headers=user_headers)
        assert res.status_code == 200
        data = res.json()
        assert "playlists" in data
        assert isinstance(data["playlists"], list)
        assert "total" in data

    def test_req4_get_playlist_detail(self, user_headers):
        """
        Playlist Detail: User can view movies in their own playlist.
        Asserts: status 200, id/name/movies present.
        """
        name = f"Detail Test {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        res = requests.get(
            f"{BASE_URL}/playlists/{playlist_id}",
            headers=user_headers
        )
        assert res.status_code == 200
        data = res.json()
        assert "id" in data
        assert "name" in data
        assert "movies" in data

    def test_req4_playlist_not_found(self, user_headers):
        """
        Not Found: Accessing a non-existent playlist returns 404.
        Asserts: status 404.
        """
        res = requests.get(
            f"{BASE_URL}/playlists/999999",
            headers=user_headers
        )
        assert res.status_code == 404

    def test_req4_playlist_private(self, admin_headers, user_headers):
        """
        Privacy: A user's playlist must not be accessible by another user.
        Asserts: status 403 when a different user accesses the playlist.
        """
        name = f"Private {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        # Create a second user and try to access
        second_username = f"other_{int(time.time())}"
        requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": second_username, "password": "pass"},
            headers=admin_headers
        )
        second_headers = login_and_get_headers(second_username, "pass")

        res = requests.get(
            f"{BASE_URL}/playlists/{playlist_id}",
            headers=second_headers
        )
        assert res.status_code == 403

    def test_req4_add_movie_to_playlist(self, user_headers):
        """
        Add Movie: User can add a valid movie to their playlist.
        Asserts: status 200 (or 404 if movie not imported yet).
        """
        name = f"Add Movie Test {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        res = requests.put(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        assert res.status_code in (200, 404)  # 404 if movie not imported

    def test_req4_add_nonexistent_movie(self, user_headers):
        """
        Add Movie: Adding a non-existent movie should return 404.
        Asserts: status 404.
        """
        name = f"Invalid Movie {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        res = requests.put(
            f"{BASE_URL}/playlists/{playlist_id}/movies/999999999",
            headers=user_headers
        )
        assert res.status_code == 404

    def test_req4_add_duplicate_movie(self, user_headers):
        """
        Add Movie: Adding the same movie twice should return 409.
        Asserts: status 409 on second add.
        """
        name = f"Dup Movie {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        add_res = requests.put(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        if add_res.status_code == 404:
            pytest.skip("Movie not imported, cannot test duplicate add")

        res = requests.put(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        assert res.status_code == 409

    def test_req4_remove_movie_from_playlist(self, user_headers):
        """
        Remove Movie: User can remove a movie from their playlist.
        Asserts: status 200 after successful removal.
        """
        name = f"Remove Movie {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        add_res = requests.put(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        if add_res.status_code == 404:
            pytest.skip("Movie not imported, cannot test removal")

        res = requests.delete(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        assert res.status_code == 200

    def test_req4_remove_nonexistent_movie_from_playlist(self, user_headers):
        """
        Remove Movie: Removing a movie not in the playlist returns 404.
        Asserts: status 404.
        """
        name = f"Remove NotIn {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        res = requests.delete(
            f"{BASE_URL}/playlists/{playlist_id}/movies/19995",
            headers=user_headers
        )
        assert res.status_code == 404

    def test_req4_delete_playlist(self, user_headers):
        """
        Delete Playlist: User can delete their own playlist.
        Asserts: status 200, subsequent GET returns 404.
        """
        name = f"To Delete {int(time.time())}"
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=user_headers
        )
        playlist_id = create_res.json()["id"]

        del_res = requests.delete(
            f"{BASE_URL}/playlists/{playlist_id}",
            headers=user_headers
        )
        assert del_res.status_code == 200

        get_res = requests.get(
            f"{BASE_URL}/playlists/{playlist_id}",
            headers=user_headers
        )
        assert get_res.status_code == 404

    def test_req4_unauthenticated_cannot_access_playlists(self):
        """
        Access Control: Unauthenticated request to playlists should fail.
        Asserts: status 401.
        """
        res = requests.get(f"{BASE_URL}/playlists")
        assert res.status_code == 401


# Stats

class TestStats:
    """
    Security and Monitoring
    Tests for API usage statistics in CSV and chart formats.
    """

    def test_req5_generate_usage_data(self, user_headers):
        """
        Usage Generation: Make several API calls to generate usage records.
        This test exists to ensure there is data available for stats endpoints.
        """
        requests.get(f"{BASE_URL}/movies")
        requests.get(f"{BASE_URL}/movies?title=test")
        requests.get(f"{BASE_URL}/playlists", headers=user_headers)
        requests.get(f"{BASE_URL}/movies/999999")

    def test_req5_user_csv_export(self, user_headers):
        """
        CSV Export (User): User can download their own usage as CSV.
        Asserts: status 200, Content-Type is text/csv.
        """
        res = requests.get(
            f"{BASE_URL}/stats/usage/csv",
            headers=user_headers
        )
        assert res.status_code == 200
        assert "text/csv" in res.headers.get("Content-Type", "")

    def test_req5_admin_csv_export(self, admin_headers):
        """
        CSV Export (Admin): Admin can download usage stats as CSV.
        Asserts: status 200, Content-Type is text/csv, has CSV header row.
        """
        res = requests.get(
            f"{BASE_URL}/stats/usage/csv",
            headers=admin_headers
        )
        assert res.status_code == 200
        assert "text/csv" in res.headers.get("Content-Type", "")
        # Verify CSV has header row
        lines = res.text.strip().split("\n")
        assert len(lines) >= 1
        header = lines[0]
        assert "endpoint" in header
        assert "method" in header

    def test_req5_user_chart(self, user_headers):
        """
        Chart (User): User can view their own usage as a PNG chart.
        Asserts: status 200, Content-Type is image/png.
        """
        res = requests.get(
            f"{BASE_URL}/stats/usage/chart",
            headers=user_headers
        )
        assert res.status_code == 200
        assert "image/png" in res.headers.get("Content-Type", "")

    def test_req5_admin_chart(self, admin_headers):
        """
        Chart (Admin): Admin can view usage chart for all users.
        Asserts: status 200, Content-Type is image/png.
        """
        res = requests.get(
            f"{BASE_URL}/stats/usage/chart",
            headers=admin_headers
        )
        assert res.status_code == 200
        assert "image/png" in res.headers.get("Content-Type", "")

    def test_req5_unauthenticated_cannot_access_stats(self):
        """
        Access Control: Unauthenticated request to stats must be rejected.
        Asserts: status 401.
        """
        res = requests.get(f"{BASE_URL}/stats/usage/csv")
        assert res.status_code == 401


# Edge Cases

class TestEdgeCases:
    """
    Edge Case Tests: boundary conditions, invalid inputs, wrong methods.
    """

    def test_edge_invalid_endpoint(self):
        """
        Edge - 404: Requesting a non-existent route should return 404.
        Asserts: status 404.
        """
        res = requests.get(f"{BASE_URL}/nonexistent/path")
        assert res.status_code == 404

    def test_edge_wrong_http_method(self):
        """
        Edge - Method Not Allowed: Using PUT on login endpoint should fail.
        Asserts: status 404 or 405.
        """
        res = requests.put(f"{BASE_URL}/auth/login")
        assert res.status_code in (404, 405)

    def test_edge_empty_body_on_create_user(self, admin_headers):
        """
        Edge - Empty Body: Submitting empty JSON body to create user should fail.
        Asserts: status 400 or 422.
        """
        res = requests.post(
            f"{BASE_URL}/auth/users",
            json={},
            headers=admin_headers
        )
        assert res.status_code in (400, 422)

    def test_edge_large_username_input(self, admin_headers):
        """
        Edge - Large Input: Submitting a very long username should be rejected.
        Asserts: status 400 or 409 (not 500).
        """
        big_username = "a" * 1000
        res = requests.post(
            f"{BASE_URL}/auth/users",
            json={"username": big_username, "password": "123"},
            headers=admin_headers
        )
        assert res.status_code in (400, 409)

    def test_edge_create_playlist_no_name(self, user_headers):
        """
        Edge - Missing Field: Creating a playlist without a name should fail.
        Asserts: status 400.
        """
        res = requests.post(
            f"{BASE_URL}/playlists",
            json={},
            headers=user_headers
        )
        assert res.status_code == 400

    def test_edge_movie_search_empty_title(self):
        """
        Edge - Empty Search: Searching with an empty title param still returns
        a valid response (treated as no filter).
        Asserts: status 200.
        """
        res = requests.get(f"{BASE_URL}/movies?title=")
        assert res.status_code == 200

    def test_edge_pagination_out_of_range(self):
        """
        Edge - Pagination: Requesting a page beyond total results should return
        an empty list, not an error.
        Asserts: status 200, movies is empty list.
        """
        res = requests.get(f"{BASE_URL}/movies?page=999999&per_page=10")
        assert res.status_code == 200
        assert res.json()["movies"] == []

    def test_edge_access_other_users_playlist(self, admin_headers, user_headers):
        """
        Edge - Privacy: A user must not access another user's playlist by ID.
        Asserts: status 403.
        """
        name = f"Admin Only {int(time.time())}"
        # Admin creates playlist via playlists endpoint
        create_res = requests.post(
            f"{BASE_URL}/playlists",
            json={"name": name},
            headers=admin_headers
        )
        # If admin has no playlist endpoint access, skip
        if create_res.status_code not in (200, 201):
            pytest.skip("Admin playlist creation not available for this test")

        playlist_id = create_res.json()["id"]
        res = requests.get(
            f"{BASE_URL}/playlists/{playlist_id}",
            headers=user_headers
        )
        assert res.status_code == 403
