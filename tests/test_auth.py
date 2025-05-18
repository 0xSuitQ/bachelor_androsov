import pytest
from auth_client import AuthClient
from dotenv import load_dotenv


@pytest.fixture
def get_user_credentials():
	return "hell", "world"

@pytest.fixture(scope="session")
def get_auth_client():
	load_dotenv()
	return AuthClient(os.getenv(AUTH_SERVER_URL))

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
	
	print(f"\nLogin result: {result}")
	
	if result.get("status") == "error":
		if "Server error" in result.get("message", ""):
			pytest.skip(f"Server error occurred: {result.get('message')}")
	
	assert result.get("status") == "success"
	assert "message" in result

def test_login(get_auth_client, get_user_credentials):
    auth_client = get_auth_client
    username, password = get_user_credentials
    result = auth_client.login(username, password)
    
    assert result.get("status") == "success"
    assert "decrypted_key" in result