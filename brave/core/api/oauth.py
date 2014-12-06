from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField
from datetime import datetime, timedelta

from brave.core.application.model import Application, ApplicationGrant
from brave.core.character.model import EVECharacter
from brave.core.account.model import User
from brave.core.util.eve import EVEKeyMask
from web.core.http import HTTPBadRequest, HTTPFound, HTTPNotFound
from brave.core.api.model import OAuthValidator
from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error
from web.core import Controller, HTTPMethod, config, session, request, response
from web.core.locale import set_lang, LanguageError, _
from web.auth import user
from marrow.util.url import URL
import ast

log = __import__('logging').getLogger(__name__)


class Authorize(HTTPMethod):

    def __init__(self):
        self._authorization_endpoint = WebApplicationServer(OAuthValidator)
        super(Authorize, self).__init__()

    def get(self, *args, **kwargs):
        uri = request.url
        http_method = 'get'
        body = request.body
        headers = request.headers

        try:
            scopes, credentials = self._authorization_endpoint.validate_authorization_request(
                uri, http_method, body, headers
            )

            session['oauth2_credentials'] = dict(
                client_id=credentials['client_id'],
                redirect_uri=credentials['redirect_uri'],
                state=credentials['state'],
                response_type=credentials['response_type'],
            )
            session.save()

            u = user._current_obj()

            # This is already checked by validate_client_id in api/model
            application = Application.objects.get(id=credentials['client_id'])

            grant = ApplicationGrant.objects(user=u, application=application).first()

            # User's already authorized this application, so we're just authenticating them and creating a new
            # access token for the application. This will look very similar to the post method below.
            if grant:
                credentials.update({'user': u})

                scopes = [c.name.replace(" ", "&") for c in grant.characters] if not grant.all_chars else ["all_chars"]
                headers, body, status = self._authorization_endpoint.create_authorization_response(
                    uri, "post", body, headers, scopes, credentials
                )
                # A new grant is created by create_authorization_response, so we delete the old one.
                grant.delete()
                raise HTTPFound(location=headers['Location'])

            if not grant:
                # TODO: We need a 'just logged in' flag in the request.

                characters = list(u.characters.order_by('name').all())
                if not len(characters):
                    return ('brave.core.template.oauthorize',
                    dict(success=False, message=_("This application requires that you have a character connected to your"
                                                  " account. Please <a href=\"/key/\">add an API key</a> to your account."),
                         ))

                if not u.has_permission(application.authorize_perm):
                    return ('brave.core.template.oauthorize',
                    dict(success=False, message=_("You do not have permission to use this application.")))

                chars = []
                for c in characters:
                    if c.credential_for(application.mask.required):
                        chars.append(c)

                if not chars:
                    return ('brave.core.template.oauthorize',
                    dict(success=False, message=_("This application requires an API key with a mask of <a href='/key/mask/{0}'>{0}</a> or better, please add an API key with that mask to your account.".format(application.mask.required)),
                         ))

                chars = [c for c in chars
                         if (c.has_verified_key or
                             config['core.require_recommended_key'].lower() == 'false')]

                if chars:
                    default = u.primary if u.primary in chars else chars[0]
                else:
                    return ('brave.core.template.oauthorize',
                        dict(success=False, message=_(
                            "You do not have any API keys on your account which match the requirements for this service. "
                            "Please add an {1} API key with a mask of <a href='/key/mask/{0}'>{0}</a> or better to your account."
                            .format(config['core.recommended_key_mask'], config['core.recommended_key_kind'])),
                            ))

                if application.require_all_chars:
                    default = 'all'

                return 'brave.core.template.oauthorize', dict(
                    success=True,
                    application=application,
                    characters=chars,
                    default=default,
                    only_one_char=application.auth_only_one_char,
                )

        except FatalClientError as e:
            return e
        except OAuth2Error as e:
            return e

    def post(self, grant=None, all_chars=False, *args, **kwargs):
        uri = request.url
        http_method = 'post'
        body = request.body
        headers = request.headers

        u = user._current_obj()

        credentials = {'user': u}
        credentials.update(session['oauth2_credentials'] if 'oauth2_credentials' in session else dict())

        application = Application.objects.get(id=credentials['client_id'])

        if not grant:
            # Deny access.
            target = application.oauth_redirect_uri
            target.query.update(dict(error="access_denied", error_description="User declined to authorize the application."))

            return 'json:', dict(success=True, location=str(target))

        characters = []

        if all_chars.lower() == 'true':
            all_chars = True
        else:
            all_chars = False

        if not all_chars and application.require_all_chars:
            return 'json:', dict(success=False, message="This application requires access to all of your characters.")

        # Require at least one character
        if 'characters[]' not in kwargs and not all_chars:
            return 'json:', dict(success=False, message="Select at least one character.")
        character_ids = kwargs['characters[]'] if 'characters[]' in kwargs else []
        # Handle only one character being authorized
        if character_ids and not isinstance(character_ids, list):
            character_ids = [character_ids]
        for character in character_ids:
            try:
                characters.append(EVECharacter.objects.get(owner=u, id=character))
            except EVECharacter.DoesNotExist:
                return 'json:', dict(success=False, message="Unknown character ID.")
            except:
                log.exception("Error loading character.")
                return 'json:', dict(success=False, message="Error loading character.")

        # OAUTH2 specifies that scopes is a string with elements separated by spaces, so we replace character
        # name spaces with an arbitrary character that is not valid in character names.
        scopes = [c.name.replace(" ", "&") for c in (characters)] if not all_chars else ["all_chars"]

        try:
            headers, body, status = self._authorization_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials
            )
            return 'json:', dict(success=True, location=headers['Location'])
        except FatalClientError as e:
            return e


class AccessToken(Controller):

    def __init__(self):
        self._token_endpoint = WebApplicationServer(OAuthValidator)
        super(AccessToken, self).__init__()

    def index(self, *args, **kwargs):
        uri = request.url
        http_method = request.method
        body = request.body
        headers = request.headers

        credentials = dict()

        headers, body, status = self._token_endpoint.create_token_response(
            uri, http_method, body, headers, credentials
        )

        return 'json:', response_from_return(headers, body, status)


def response_from_return(headers, body, status):
    response.status_int = status
    response.headers.update(headers)

    # This is a workaround because we use 401 internally to mean redirect to the auth page
    # TODO: We should probably fix this
    if response.status_int == 401:
        response.status_int = 400

    return ast.literal_eval(body)

def response_from_error(e):
    raise HTTPBadRequest(message='An error occurred: {}'.format(e.description))

class OAuth(Controller):
    authorize = Authorize()
    access_token = AccessToken()