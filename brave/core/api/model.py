# encoding: utf-8

from __future__ import unicode_literals

from datetime import datetime, timedelta
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField
from oauthlib.oauth2 import RequestValidator

from brave.core.util.signal import update_modified_timestamp
from brave.core.application.signal import trigger_private_key_generation
from brave.core.util.field import PasswordField, IPAddressField
from brave.core.application.model import Application, ApplicationGrant
from brave.core.character.model import EVECharacter
from brave.core.api.util import parse_http_basic


log = __import__('logging').getLogger(__name__)


class AuthenticationBlacklist(Document):
    meta = dict(
            allow_inheritance = False,
            indexes = [
                    'scheme',
                    'protocol',
                    'domain',
                    'port'
                ]
        )
    
    scheme = StringField('s')
    protocol = StringField('p')
    domain = StringField('d')
    port = StringField('o')
    
    creator = ReferenceField('User')  # TODO: Nullify inverse deletion rule.


class AuthenticationRequest(Document):
    meta = dict(
            allow_inheritance = False,
            indexes = [
                    dict(fields=['expires'], expireAfterSeconds=0)
                ]
        )
    
    application = ReferenceField('Application', db_field='a')
    user = ReferenceField('User', db_field='u')
    grant = ReferenceField('ApplicationGrant', db_field='g')
    
    success = URLField(db_field='s')
    failure = URLField(db_field='f')
    
    expires = DateTimeField(db_field='e', default=lambda: datetime.utcnow() + timedelta(minutes=10))
    
    def __repr__(self):
        return 'AuthenticationRequest({0}, {1}, {2}, {3})'.format(self.id, self.application, self.user, self.grant)

class AuthorizationCode(Document):
    meta = dict(
            allow_inheritance = False,
            indexes = [
                    dict(fields=['expires'], expireAfterSeconds=0)
                ]
        )

    application = ReferenceField('Application', db_field='a')
    user = ReferenceField('User', db_field='u')
    code = StringField(db_field='c')
    scopes = ListField(StringField(db_field='s'))
    state = StringField(db_field='t')

    redirect_uri = URLField(db_field='r')

    expires = DateTimeField(db_field='e', default=lambda: datetime.utcnow() + timedelta(minutes=10))

    def __repr__(self):
        return 'AuthorizationCode({0}, {1}, {2}, {3})'.format(self.id, self.application, self.user, self.redirect_uri)


class OAuthValidator(RequestValidator):

    @staticmethod
    def verify_http_basic(request):
        id, secret = parse_http_basic(request)

        client = OAuthValidator.verify_id_and_secret(id, secret)

        if not client:
            return False

        request.client = client
        return client

    @staticmethod
    def verify_http_attributes(request):
        if not hasattr(request, 'client_id') or not hasattr(request, 'client_secret'):
            return False

        client = OAuthValidator.verify_id_and_secret(request.client_id, request.client_secret)

        if not client:
            return False

        request.client = client
        return client


    @staticmethod
    def verify_id_and_secret(client_id, client_secret):
        try:
            app = Application.objects.get(id=client_id)
        except Application.DoesNotExist:
            return False

        # Prevent timing attacks against the client secret
        # We could also try getting the application from MongoDB with the secret as an attribute, but not sure
        # if that would protect against timing attacks.

        value = True

        for p, k in zip(client_secret, app.oauth_client_secret):
            if p != k:
                value = False

        if not value:
            return False

        return app

    @staticmethod
    def authenticate_client(request, *args, **kwargs):
        # HTTPBasic Authentication
        if 'Authorization' in request.headers:
            log.debug("HTTPAuthorization Header Detected.")
            return OAuthValidator.verify_http_basic(request)
        # GET or POST attributes
        if hasattr(request, 'client_id') and hasattr(request, 'client_secret'):
            log.debug("Client Credentials in args detected.")
            return OAuthValidator.verify_http_attributes(request)

        return False


    @staticmethod
    def authenticate_client_id(request, *args, **kwargs):
        # At the moment we only support confidential clients.
        return False

    @staticmethod
    def client_authentication_required(request, *args, **kwargs):
        # At the moment we only support confidential clients.
        return True

    @staticmethod
    def confirm_redirect_uri(client_id, code, redirect_uri, client, *args, **kwargs):
        if redirect_uri != client.oauth_redirect_uri:
            return False

        return True

    @staticmethod
    def get_default_redirect_uri(client_id, request, *args, **kwargs):
        return request.client.oauth_redirect_uri

    @staticmethod
    def get_default_scopes(client_id, request, *args, **kwargs):
        return None

    @staticmethod
    def get_original_scopes(refresh_token, request, *args, **kwargs):
        try:
            grant = ApplicationGrant.objects.get(refresh_token=refresh_token, application=request.client)
        except ApplicationGrant.DoesNotExist:
            return False

        return grant.characters

    @staticmethod
    def invalidate_authorization_code(client_id, code, request, *args, **kwargs):
        try:
            ar = AuthorizationCode.objects.get(code=code)
        except AuthorizationCode.DoesNotExist:
            return

        ar.delete()
        return

    @staticmethod
    def is_within_original_scope(request_scopes, refresh_token, request, *args, **kwargs):
        try:
            grant = ApplicationGrant.objects.get(refresh_token=refresh_token, application=request.client)
        except ApplicationGrant.DoesNotExist:
            return False

        return all(c in grant.characters for c in request_scopes)

    @staticmethod
    def revoke_token(token, token_type_hint, request, *args, **kwargs):
        if token_type_hint == "access_token":
            try:
                grant = ApplicationGrant.objects.get(access_token=token)
            except ApplicationGrant.DoesNotExist:
                return

            grant.access_token = None
        elif token_type_hint == "refresh_token":
            try:
                grant = ApplicationGrant.objects.get(refresh_token=token)
            except ApplicationGrant.DoesNotExist:
                return

            grant.refresh_token = None

    @staticmethod
    def rotate_refresh_token(request):
        return True

    @staticmethod
    def save_authorization_code(client_id, code, request, *args, **kwargs):
        ar = AuthorizationCode(code=code['code'], application=request.client, user=request.user,
                               redirect_uri=request.redirect_uri, scopes=request.scopes, state=request.state)
        ar.save()
        return request.client.oauth_redirect_uri

    @staticmethod
    def save_bearer_token(token, request, *args, **kwargs):
        all_chars = "all_chars" in request.scopes
        chars = [EVECharacter.objects.get(name=c.replace("&", " ")) for c in (request.scopes if not all_chars else [q.name for q in request.user.characters])]

        grant = ApplicationGrant(user=request.user, _mask=request.client.mask.required, application=request.client,
                                 expires=datetime.utcnow()+timedelta(days=request.client.expireGrantDays),
                                 oauth_access_token=token['access_token'],
                                 oauth_refresh_token=token['refresh_token'] if 'refresh_token' in token else None,
                                 chars=chars, all_chars=all_chars)
        grant.save()
        return request.client.oauth_redirect_uri

    @staticmethod
    def validate_bearer_token(token, scopes, request):
        try:
            token = ApplicationGrant.objects.get(access_token=token)
        except ApplicationGrant.DoesNotExist:
            return False

        all(c.replace("&", " ") in token.characters for c in scopes)

        return True

    @staticmethod
    def validate_client_id(client_id, request, *args, **kwargs):

        try:
            app = Application.objects.get(id=client_id)
        except Application.DoesNotExist:
            return False

        request.client = app
        return True

    @staticmethod
    def validate_code(client_id, code, client, request, *args, **kwargs):
        try:
            ar = AuthorizationCode.objects.get(code=code)
        except AuthorizationCode.DoesNotExist:
            log.warning("Authorization Code {} not found.".format(code))
            return False

        if ar.application != client:
            log.warning("APPLICATION DOESN'T MATCH CLIENT")
            return False

        if ar.application.client_id != client_id:
            log.warning("CLIENT ID DOESN'T MATCH APP ID")
            return False

        request.user = ar.user
        request.scopes = ar.scopes
        request.state = ar.state

        return True

    @staticmethod
    def validate_grant_type(client_id, grant_type, client, request, *args, **kwargs):
        if client.oauth_grant_type and grant_type == client.oauth_grant_type:
            return True

        return False

    @staticmethod
    def validate_redirect_uri(client_id, redirect_uri, request, *args, **kwargs):
        if request.client.oauth_redirect_uri == redirect_uri:
            return True
        return False

    @staticmethod
    def validate_refresh_token(refresh_token, client, request, *args, **kwargs):
        try:
            grant = ApplicationGrant.objects.get(refresh_token=refresh_token, application=client)
        except ApplicationGrant.DoesNotExist:
            return False

        return all(c.replace("&", " ") in grant.characters for c in request.scopes)

    @staticmethod
    def validate_response_type(client_id, response_type, client, request, *args, **kwargs):
        if response_type == "code":
            return True

    @staticmethod
    def validate_scopes(client_id, scopes, client, request, *args, **kwargs):
        return True

    @staticmethod
    def validate_user(username, password, client, request, *args, **kwargs):
        raise NotImplementedError()