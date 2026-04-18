from azurefox.errors import ErrorKind, classify_exception


def test_classify_exception_maps_unauthorized_to_auth_failure() -> None:
    assert classify_exception(Exception("401 Unauthorized")) == ErrorKind.AUTH_FAILURE
