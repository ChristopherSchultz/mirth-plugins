# Mirth Connect authentication workflow notes

This was a little difficult to reverse-engineer because Mirth's classes and
interfaces aren't documented and there aren't really any guides to developing
authentication plug-ins.

## First Leg
When the client attempts a login, the server routes the attempt to
`com.mirth.connect.server.api.servlets.UserServlet.login(String, String)`
which calls `com.mirth.connect.server.controllers.UserController.authorizeUser(String, String)`
to check the username/password against the local user database or some other
authentication plug-in. Usually, this is handled by
`com.mirth.connect.server.controllers.DefaultUserController`.

Once `com.mirth.connect.server.controllers.DefaultUserController.authorizeUser(String,String)`
checks the username+password, it calls
`com.mirth.connect.server.controllers.DefaultUserController.handleSecondaryAuthentication(String, LoginStatus, LoginRequirementsChecker)`.
 If the primary authentication was successful and there is a MFA plug-in of
 any kind, that plug-in's
 `com.mirth.connect.plugins.MultiFactorAuthenticationPlugin.authenticate(String, LoginStatus)`
 method is called with the "primary" `LoginStatus` object, whose status will likely be SUCCESS.

Now, it's time for the MFA plug-in to decide what to do. It has two choices:

1. Return the `LoginStatus` unchanged; this allows the user to proceed and the workflow is done.
2. Return an `ExtendedLoginStatus` object which specifies the client-side
   plug-in class to invoke for the next leg of the process. The status
   should be FAIL, and can change the user's username for the next stage if
   necessary. A "message" can also be sent along with the response to the
   client.

## Second Leg
The client receives this error:

    com.mirth.connect.client.core.UnauthorizedException: HTTP/1.1 401 Unauthorized
	   at com.mirth.connect.client.core.ServerConnection.handleResponse(ServerConnection.java:477)
	   at com.mirth.connect.client.core.ServerConnection.executeSync(ServerConnection.java:256)
	   at com.mirth.connect.client.core.ServerConnection.apply(ServerConnection.java:166)

... and the client's plug-in (specified above in the `ExtendedLoginStatus`
returned to the client) has its
`net.christopherschultz.mirth.plugins.auth.mfa.MFAAuthenticationClientPlugin.authenticate(Window, Client, String, LoginStatus)`
method invoked. This includes the user's username and the `ExtendedLoginStatus`
that came from the server. The status will be FAIL and the "message" will be
whatever the server sent as a part of that `ExtendedLoginStatus`.

Now is the chance for the client-side plug-in to take whatever action makes
sense. For MFA, we ask the user for a token. The thread calling `authenticate`
isn't on the AWT event thread, so it's okay to e.g. show a pop-up window,
make web-service calls, etc.

Once the client-side plug-in is ready to proceed with the next step, it should
re-authenticate with the server by calling
`com.mirth.connect.client.core.api.servlets.UserServletInterface.login(String, String)`
with the user's username and a `null` password. But you should include an HTTP
header in the call with the name `X-Mirth-Login-Data` (defined in
`com.mirth.connect.client.core.api.servlets.UserServletInterface.LOGIN_DATA_HEADER`)
which contains "additional" authentication information bound for your
server-side plug-in.

You can pack whatever data you need in this plug-in. You may find that you
need quite a bit more than you originally thought, since the second login
call, here, (a) doesn't have access to the user's password from the previous
leg and (b) must provide 100% of the information necessary to authenticate
the user on the server.

**Security Note**: Remember that any client can call
`com.mirth.connect.client.core.api.servlets.UserServletInterface.login(String, String)`
with this special HTTP header. If the server-side relies solely upon the
contents of that header for authentication, you'd better make sure it can't
be forged, replayed, etc. by a malicious client.

## Third Leg

Similar to the first leg, the `UserServlet` and `DefaultUserController` are
involved. But this time, because of the presence of the `X-Mirth-Login-Data`
HTTP header, the `DefaultUserController` sends the username and that header
value directly to the MFA plug-in's
`com.mirth.connect.plugins.MultiFactorAuthenticationPlugin.authenticate(String)`
method. There is no re-check of the username+password, so your plug-in
needs to make sure that the information about the username+password check
being successful is somehow carried-through the header. (See my MFA plug-in
implementation for how I solved that particular problem.)

Here, the plug-in does whatever it wants and returns a `LoginStatus`. Return
FAIL to cause the login to fail, or SUCCESS to cause it to succeed.

## Conclusion

Even going back through the code to firm-up these NOTEs caused me some
confusion due to the two different behaviors when calling `login()`, with
or without the `X-Mirth-Login-Data` header. A close read of the code is
necessary to follow it along, and it really helped to have folks from the
Mirth community give me some pointers and help me navigate through all
this. I've put their names in the README.md file at the top-level of this
repository.
