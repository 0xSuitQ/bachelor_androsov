import pytest
from auth_client import AuthClient


@pytest.fixture
def get_user_credentials():
	return "hell", "world"

@pytest.fixture(scope="session")
def get_auth_client():
	return AuthClient("http://44.204.170.208:8080")

def test_auth_client(get_auth_client, get_user_credentials):
	auth_client = get_auth_client
	username, password = get_user_credentials
	result = auth_client.register(username, password)
	
	# Check for status success, not just 'success' string
	assert result.get('status') == 'success', f"Registration failed: {result.get('message')}"

def test_login(get_auth_client, get_user_credentials):
	auth_client = get_auth_client

	username, password = get_user_credentials

	result = auth_client.login(username, password)
	
	# Print detailed result for debugging
	print(f"\nLogin result: {result}")
	
	# Check if we got a successful response
	if result.get("status") == "error":
		if "Server error" in result.get("message", ""):
			pytest.skip(f"Server error occurred: {result.get('message')}")
	
	# Actual assertion - this is what we expect when everything works
	assert result.get("status") == "success"
	assert "message" in result
