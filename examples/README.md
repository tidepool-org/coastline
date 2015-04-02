Tidepool OAuth 2.0
=========


Apps connect to Tidepool using OAuth 2.0, the standard used by most APIs for authenticating and authorizing users.

## Initial Setup

Before you can start using OAuth2 with your application, you’ll need to tell Tidepool a bit of information about your application

### Register your application here.

http://localhost:8009/oauth/v1/signup


Set your application name
Set your redirect url
Select your scope

Create a platform user
* email
* password

Make a note of both your client_id and client_secret.

* Redirect URI: The redirect URI is the URL within your application that will receive the OAuth2 credentials.
* Scopes:
  * Select the “Request upload of data on behalf” scope .
  * Select the “Request viewing of data” scope .


## The First Leg

First, direct your user to http://localhost:8009/oauth/v1/authorize through a GET request with the following parameters:

Parameters: For GET, include them as query parameters, please URL encode the parameters.
response_type
required	Whether the endpoint returns an authorization code. For web applications, a value of ``code`` should be used.
client_id
required	The client_id you obtained in the Initial Setup.
redirect_uri	An HTTPS URI or custom URL scheme where the response will be redirected. Must be registered with Tidepool in the application console. 
state
required	An arbitrary string of your choosing that will be included in the response to your application. Anything that might be useful for your application can be included.

A sample GET request could therefore look like:
```
http://localhost:8009/oauth/v1/authorize?response_type=code&client_id=8de198a3f9&scope=view&redirect_uri=http%3A%2F%2Flocalhost%3A14000%2Fclient%2Fappauth%2Fcode
```

## The User Experience

....

