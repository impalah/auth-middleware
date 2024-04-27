from urllib.parse import quote


def get_login_url(
    domain: str,
    client_id: str,
    region: str,
    redirect_uri: str,
) -> str:
    """Returns the Cognito login URL

    Args:
        domain (str): domain name
        client_id (str): client id from Cognito
        region (str): aws region
        redirect_uri (str): redirect URI

    Returns:
        str: login URL
    """

    encoded_uri = quote(redirect_uri, safe="")
    return f"https://{domain}.auth.{region}.amazoncognito.com/login?client_id={client_id}&response_type=token&scope=email+openid+phone+profile&redirect_uri={encoded_uri}"


def get_logout_url(
    domain: str,
    client_id: str,
    region: str,
    redirect_uri: str,
) -> str:
    """Returns the Cognito logout URL

    Args:
        domain (str): domain name
        client_id (str): client id from Cognito
        region (str): aws region
        redirect_uri (str): redirect URI

    Returns:
        str: logout URL
    """

    encoded_uri = quote(redirect_uri, safe="")
    return f"https://{domain}.auth.{region}.amazoncognito.com/logout?client_id={client_id}&response_type=token&redirect_uri={encoded_uri}"
