export const RESERVED_COMMUNICATION_TYPES = [
  "Identification", "IdentificationResponse", "Register", "RegisterResponse",
  "Challenge", "ChallengeResponse", "Ping", "Pong", "Disconnect", "Redirect",
  "Shutdown", "Error", "ErrorParsing", "ErrorBadVersion", "BadRequest",
  "Unauthorized", "Forbidden", "NotFound", "TooManyRequests", "InternalServerError",
  "BadGateway", "ServiceUnavailable", "GatewayTimeout", "PipeRequest", "PipeResponse",
  "PipeAbort",
] as const;

export const RESERVED_DATA_TYPES = [
  "Version", "Id", "ClientNonce", "ServerNonce", "PublicKeys", "Signature",
  "PqSignature", "Description", "Connected", "Timestamp", "Error", "ErrorParsing",
  "ErrorMessage", "Accepted", "RequirePq",
] as const;

export const FIRST_USER_TYPE_ID = 32;
