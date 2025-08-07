from auth_middleware.providers.cognito.utils import get_login_url, get_logout_url


def test_cognito_get_login_url():
    # Test case 1: Check if the login URL is generated correctly
    domain = "example"
    client_id = "1234567890"
    region = "us-west-2"
    redirect_uri = "https://example.com/callback"
    expected_url = "https://example.auth.us-west-2.amazoncognito.com/login?client_id=1234567890&response_type=token&scope=email+openid+phone+profile&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"

    assert get_login_url(domain, client_id, region, redirect_uri) == expected_url

    # Test case 2: Check if the login URL is generated correctly
    # with special characters in the redirect URI
    domain = "example"
    client_id = "1234567890"
    region = "us-west-2"
    redirect_uri = "https://example.com/callback?param=value&param2=value2"
    expected_url = "https://example.auth.us-west-2.amazoncognito.com/login?client_id=1234567890&response_type=token&scope=email+openid+phone+profile&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue%26param2%3Dvalue2"

    assert get_login_url(domain, client_id, region, redirect_uri) == expected_url


def test_cognito_get_logout_url():
    # Test case 1: Check if the logout URL is generated correctly
    domain = "example"
    client_id = "1234567890"
    region = "us-west-2"
    redirect_uri = "https://example.com/callback"
    expected_url = "https://example.auth.us-west-2.amazoncognito.com/logout?client_id=1234567890&response_type=token&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"

    assert get_logout_url(domain, client_id, region, redirect_uri) == expected_url

    # Test case 2: Check if the logout URL is generated correctly
    # with special characters in the redirect URI
    domain = "example"
    client_id = "1234567890"
    region = "us-west-2"
    redirect_uri = "https://example.com/callback?param=value&param2=value2"
    expected_url = "https://example.auth.us-west-2.amazoncognito.com/logout?client_id=1234567890&response_type=token&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue%26param2%3Dvalue2"

    assert get_logout_url(domain, client_id, region, redirect_uri) == expected_url
