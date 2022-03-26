# ras_auth

Microservice for authentication, used together with ras_service

Sqlite table: create table users(name text primary key, password text, role int).

Registration: 
POST
{
	"name": "some_name",
	"password": "some_password"
}

Login (generate new access and refresh tokens):
POST
{
	"name": "some_name",
	"password": "some_password"
}

Refresh (generate new access and refresh tokens):
POST
{
	"token": "some_refresh_token"
}

Change role (allow on 0000_0110 bitmask):
POST
{
	"token": "some_access_token",
	"name": "some_name",
	"role": "2"
}

Get public key (allow on 0000_0001 bitmask):
POST
{
	"token": "some_access_token"
}