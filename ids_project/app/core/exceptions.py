"""
Custom exception classes for the IDS application.

Each exception maps to an HTTP status code and provides
structured error information for API responses.
"""


class IDSBaseException(Exception):
    """Base exception for all IDS application errors."""

    status_code: int = 500
    error_type: str = "internal_error"

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        """Convert exception to API-friendly dictionary."""
        response = {
            "error": self.error_type,
            "message": self.message,
        }
        if self.details:
            response["details"] = self.details
        return response


class ValidationError(IDSBaseException):
    """Raised when input validation fails.

    HTTP 400 Bad Request.
    """

    status_code = 400
    error_type = "validation_error"


class AuthenticationError(IDSBaseException):
    """Raised when authentication fails.

    HTTP 401 Unauthorized.
    """

    status_code = 401
    error_type = "authentication_error"


class AuthorizationError(IDSBaseException):
    """Raised when user lacks required permissions.

    HTTP 403 Forbidden.
    """

    status_code = 403
    error_type = "authorization_error"


class NotFoundError(IDSBaseException):
    """Raised when a requested resource does not exist.

    HTTP 404 Not Found.
    """

    status_code = 404
    error_type = "not_found"


class ConflictError(IDSBaseException):
    """Raised when an operation conflicts with existing state.

    HTTP 409 Conflict. Example: creating a user with duplicate username.
    """

    status_code = 409
    error_type = "conflict"


class RateLimitError(IDSBaseException):
    """Raised when rate limit is exceeded.

    HTTP 429 Too Many Requests.
    """

    status_code = 429
    error_type = "rate_limit_exceeded"


class ServiceUnavailableError(IDSBaseException):
    """Raised when an external service is unavailable.

    HTTP 503 Service Unavailable. Example: database connection failure.
    """

    status_code = 503
    error_type = "service_unavailable"
