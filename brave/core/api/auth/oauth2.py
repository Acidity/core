from brave.core.api.auth.model import AuthorizationMethod
from brave.core.application.model import Application, ApplicationGrant
from brave.core.api.model import OAuthValidator

from web.core.http import HTTPBadRequest
from web.core import session
from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error
import ast


log = __import__('logging').getLogger(__name__)


class OAuth2AuthorizationCode(AuthorizationMethod):
    name = "OAuth2 Authorization Code"

    short = "oauth2_auth_code"

    #TODO: fix
    application_grant = ApplicationGrant

    # OAuthlib authorization endpoint
    _authorization_endpoint = WebApplicationServer(OAuthValidator)

    additional_methods = ['access_token']

    @classmethod
    def pre_authorize(cls, user, app, request, *args, **kw):
        uri = request.url
        http_method = request.method
        body = request.body
        headers = request.headers

        try:
            scopes, credentials = cls._authorization_endpoint.validate_authorization_request(
                uri, http_method, body, headers
            )

            session['oauth2_credentials'] = dict(
                client_id=credentials['client_id'],
                redirect_uri=credentials['redirect_uri'],
                state=credentials['state'],
                response_type=credentials['response_type'],
            )
            session.save()

        #TODO: Fix
        except FatalClientError as e:
            return e
        except OAuth2Error as e:
            return e

    @classmethod
    def authorize(cls, user, app, request, characters, all_chars, *args, **kw):
        uri = request.url
        http_method = request.method
        body = request.body
        headers = request.headers

        credentials = {'user': user}
        credentials.update(session['oauth2_credentials'] if 'oauth2_credentials' in session else dict())

        # OAUTH2 specifies that scopes is a string with elements separated by spaces, so we replace character
        # name spaces with an arbitrary character that is not valid in character names.
        scopes = [c.name.replace(" ", "&") for c in (characters)] if not all_chars else ["all_chars"]

        try:
            headers, body, status = cls._authorization_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials
            )
            return 'json:', dict(success=True, location=headers['Location'])
        except FatalClientError as e:
            return e

    @classmethod
    def deny_authorize(cls, user, app, request, *args, **kw):
        raise HTTPBadRequest(error="access_denied", error_description="The user declined to authorize your application"
                                                                      " to access their data.")

    @classmethod
    def authenticate(cls, user, app, request, *args, **kwargs):
        grant = ApplicationGrant.objects.get(user=user, application=app)
        ret = cls.authorize(user, app, request, grant.characters, grant.all_chars, *args, **kwargs)
        grant.delete()
        return ret[1]['location']

    @classmethod
    def get_application(cls, request, *args, **kw):
        if 'client_id' in kw:
            return Application.objects.get(id=kw['client_id'])
        if 'Authorization' in request.headers:
            return OAuthValidator.verify_http_basic(request.headers['Authorization'])

    @classmethod
    def access_token(cls, *args, **kwargs):
        from web.core import request
        uri = request.url
        http_method = request.method
        body = request.body
        headers = request.headers

        credentials = dict()

        headers, body, status = cls._authorization_endpoint.create_token_response(
            uri, http_method, body, headers, credentials
        )

        return 'json:', cls.response_from_return(headers, body, status)

    @staticmethod
    def response_from_return(headers, body, status):
        from web.core import response
        response.status_int = status
        response.headers.update(headers)

        # This is a workaround because we use 401 internally to mean redirect to the auth page
        # TODO: We should probably fix this
        if response.status_int == 401:
            response.status_int = 400

        return ast.literal_eval(body)