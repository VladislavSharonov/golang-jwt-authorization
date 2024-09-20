# JWT Authorization In GoLang 

## Technologies:

* Go
* JWT
* PostgreSQL
* Docker

## Task

Write a part of the authentication service.

Two REST routes:
* The first route issues a pair of Access, Refresh tokens for the user with the identifier (GUID) specified in the request parameter
* The second route performs a Refresh operation on a pair of Access, Refresh tokens

## Requirements:

Access token type JWT, algorithm SHA512, is strictly prohibited to store in the database.

Refresh token type is arbitrary, the transfer format is base64, is stored in the database exclusively as a bcrypt hash, must be protected from modification on the client side and attempts to reuse.

Access, Refresh tokens are mutually linked, the Refresh operation for an Access token can only be performed by the Refresh token that was issued with it.

The payload of the tokens must contain information about the IP address of the client to whom it was issued. If the IP address has changed, an email warning must be sent to the user's email during the refresh operation (for simplicity, you can use mock data).
