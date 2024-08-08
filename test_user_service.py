import subprocess
import json

def test_register_user():
    url = "http://localhost:8080/users/register"
    headers = {"Content-Type": "application/json"}
    data = {
        "username": "testuser",
        "password": "password123",
        "email": "testuser@example.com"
    }
    response = subprocess.run(["curl", "-X", "POST", url, "-H", json.dumps(headers), "-d", json.dumps(data)], capture_output=True, text=True)
    print(response.stdout)
    assert response.returncode == 0

def test_login_user():
    url = "http://localhost:8080/users/login"
    headers = {"Content-Type": "application/json"}
    data = {
        "username": "testuser",
        "password": "password123"
    }
    response = subprocess.run(["curl", "-X", "POST", url, "-H", json.dumps(headers), "-d", json.dumps(data)], capture_output=True, text=True)
    print(response.stdout)
    assert response.returncode == 0

if __name__ == "__main__":
    test_register_user()
    test_login_user()
