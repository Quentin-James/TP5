import pytest
import httpx
from fastapi.testclient import TestClient
from api.app import app  # Assurez-vous que cet import pointe vers l'application FastAPI

client = TestClient(app)
total_points = 10
score = 0


# Tests pour la fonctionnalité de base de l'API
@pytest.mark.feature("Base API")
@pytest.mark.parametrize("endpoint, expected_status, expected_response", [
    ("/", 200, {}),  # Test de la route principale
])
def test_base_api(endpoint, expected_status, expected_response):
    global score
    response = client.get(endpoint)
    assert response.status_code == expected_status
    assert response.json() == expected_response
    score += 1


# Tests pour la fonctionnalité d'addition
@pytest.mark.feature("Addition")
@pytest.mark.parametrize("a, b, expected_result", [
    (5, 10, 15),
    (3, 7, 10),
])
def test_miscellaneous_addition(a, b, expected_result):
    global score
    response = client.get(f"/miscellaneous/addition?a={a}&b={b}")
    assert response.status_code == 200
    assert response.json() == {"result": expected_result}
    score += 1


# Tests pour la création d'utilisateur
@pytest.mark.feature("User Management")
@pytest.mark.parametrize("username, password, expected_response", [
    ("user1", "password123", {"username": "user1", "todo_count": 0}),
])
def test_create_user(username, password, expected_response):
    global score
    response = client.post("/users", json={"username": username, "password": password})
    assert response.status_code == 201
    assert response.json() == expected_response
    score += 2


# Tests pour l'authentification et la récupération de l'utilisateur
@pytest.mark.feature("Authentication")
@pytest.mark.parametrize("username, password", [
    ("user1", "password123"),
])
def test_auth_and_get_user(username, password):
    global score
    response = client.post("/token", data={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json().get("access_token")

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"username": username, "todo_count": 0}
    score += 3


# Tests pour l'ajout de TODO
@pytest.mark.feature("TODO Management")
@pytest.mark.parametrize("todo_data,auth", [
    ({"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 1}, False),
    ({"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 1}, True),
])
def test_add_todo(todo_data, auth):
    global score
    headers = {}
    if auth:
        response = client.post("/token", data={"username": "user1", "password": "password123"})
        token = response.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/users/me/todo", json=todo_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["name"] == todo_data["name"]
    score += 2


# Tests pour la récupération des TODO triés
@pytest.mark.feature("TODO Retrieval")
@pytest.mark.parametrize("auth", [True, False])
def test_get_todo_list(auth):
    global score
    headers = {}
    if auth:
        response = client.post("/token", data={"username": "user1", "password": "password123"})
        token = response.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/users/me/todo", headers=headers)
    assert response.status_code == 200
    todos = response.json()
    assert len(todos) > 0
    assert todos[0]["priority"] == 1  # Vérification du tri par priorité
    score += 1


# Tests pour la modification des TODO
@pytest.mark.feature("TODO Update")
@pytest.mark.parametrize("todo_data, updated_data, auth", [
    (
            {"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 1},
            {"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 20},
            True
    ),
    (
            {"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 1},
            {"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 20},
            False
    )
])
def test_update_todo(todo_data, updated_data, auth):
    global score
    headers = {}
    if auth:
        response = client.post("/token", data={"username": "user1", "password": "password123"})
        token = response.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/users/me/todo", json=todo_data, headers=headers)
    todo_id = response.json()["id"]

    response = client.patch(f"/users/me/todo/{todo_id}", json=updated_data, headers=headers)
    assert response.status_code == 200

    response = client.get(f"/users/me/todo/", headers=headers)
    assert response.json()[1]["priority"] == updated_data["priority"]
    score += 1


# Tests pour la suppression des TODO
@pytest.mark.feature("TODO Deletion")
def test_delete_todo():
    global score
    response = client.post("/token", data={"username": "user1", "password": "password123"})
    token = response.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    todo_data = {"name": "Acheter du lait", "description": "Aller au supermarché", "priority": 1}
    response = client.post("/users/me/todo", json=todo_data, headers=headers)
    todo_id = response.json()["id"]

    response = client.delete(f"/users/me/todo/{todo_id}", headers=headers)
    assert response.status_code == 204
    score += 1


# Afficher la note finale
def test_score():
    print(f"Note de l'étudiant : {score} / {total_points}")