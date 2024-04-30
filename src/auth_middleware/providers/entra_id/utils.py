from urllib.parse import quote


def get_login_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str = None,
    nonce: str = None,
) -> str:
    """Returns the Entra ID login URL

    Args:
        tenant_id (str): Azure tenant id
        client_id (str): application client id from Entra Id
        redirect_uri (str): redirect URI
        state (str): just a random string
        nonce (str): just a random numeric string

    Returns:
        str: login URL
    """

    if not state:
        state = "1234567890"
    if not nonce:
        nonce = "9876543210"

    encoded_uri = quote(redirect_uri, safe="")
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?client_id={client_id}&response_type=id_token%20token&redirect_uri={encoded_uri}&scope=openid%20email%20profile&state={state}&nonce={nonce}"


def get_logout_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
) -> str:
    """Returns the Entra ID logout URL

    Args:
        tenant_id (str): Azure tenant id
        client_id (str): application client id from Entra Id
        redirect_uri (str): redirect URI

    Returns:
        str: logout URL
    """

    # encoded_uri = quote(redirect_uri, safe="")
    return ""
    # return f"https://{domain}.auth.{region}.amazoncognito.com/logout?client_id={client_id}&response_type=token&redirect_uri={encoded_uri}"
