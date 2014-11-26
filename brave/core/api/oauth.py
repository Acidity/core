from web.core import request, response, url, config, Controller
from brave.core.api.model import AuthenticationBlacklist, OAuthenticationRequest
from brave.core.api.util import SignedController
from marrow.util.convert import boolean
from marrow.util.url import URL
from mongoengine import Q
from operator import __or__
from brave.core.application.model import Application
from web.core.http import HTTPBadRequest, HTTPFound, HTTPNotFound
from datetime import datetime
import requests


log = __import__('logging').getLogger(__name__)


class OAuthAPI(Controller):

    def authorize(self, response_type=None, redirect_uri=None, client_id=None, scope=None, state=None, **kwargs):
        """Prepare a incoming session request.

        Error 'message' attributes are temporary; base your logic on the status and code attributes.

        success: web.core.url:URL (required)
        failure: web.core.url:URL (required)

        returns:
            location: web.core.url:URL
                the location to direct users to
        """

        # TODO: Update so errors get redirected to client

        if response_type is None:
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.failure.missing',
                    message = "Response Type is missing from your request."
                )

        # TODO: Support other OAuth authentication types.
        if response_type != "code":
            raise NotImplementedError()

        if client_id is None and response_type == "code":
            """ In the "authorization_code" "grant_type" request to the token endpoint, an
                unauthenticated client MUST send its "client_id" to prevent itself
                from inadvertently accepting a code intended for a client with a
                different "client_id".
                - RFC 6749 Section 3.2.1
            We're going to enforce it server side as well."""

            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.failure.missing',
                    message = "Client ID is missing."
                )

        try:
            app = Application.objects.get(id=client_id)
        except Application.DoesNotExist:
            return dict(
                error="invalid_request",
                error_description="Application with provided client_id was not found.",
            )
        if redirect_uri and

        service = Application.objects.get(id=client_id)

        # Also ensure they are valid URIs.

        try:
            redirect_uri_ = redirect_uri
            redirect_uri = URL(redirect_uri)
        except:
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.malformed',
                    message = "Successful authentication URL is malformed."
                )

        if response_type != "code":
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.malformed',
                    message = "response_type must be set to 'code'"
                )

        # Deny localhost/127.0.0.1 loopbacks and 192.* and 10.* unless in development mode.

        if not boolean(config.get('debug', False)) and (redirect_uri.host in ('localhost', '127.0.0.1') or \
                redirect_uri.host.startswith('192.168.') or \
                redirect_uri.host.startswith('10.')):
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'development-only',
                    message = "Loopback and local area-network URLs disallowd in production."
                )

        # Check blacklist and bail early.

        if AuthenticationBlacklist.objects(reduce(__or__, [
                    Q(scheme=redirect_uri.scheme), Q(protocol=redirect_uri.port or redirect_uri.scheme),
                ] + ([] if not redirect_uri.host else [
                    Q(domain=redirect_uri.host)
                ])
                )).count():
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'blacklist',
                    message = "You have been blacklisted.  To dispute, contact {0}".format(config['mail.blackmail.author'])
                )

        # TODO: Check DNS.  Yes, really.

        # Generate authentication token.

        log.info("Creating OAUTH request for {0} with callbacks {1}".format(service, redirect_uri_))
        ar = OAuthenticationRequest(
                service,
                redirect_uri = redirect_uri_,
                state=state,
                scope=scope
            )
        ar.save()

        raise HTTPFound(location=url.complete('/oauthorize/{0}'.format(ar.id)))

        return dict(
                location = url.complete('/oauthorize/{0}'.format(ar.id))
            )

    def access_token(self, grant_type=None, code=None, redirect_uri=None, client_id=None):
        print "GETTING ACCESS_TOKEN"
        if grant_type is None:
            log.debug("grant_type missing")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.missing',
                    message = "grant_type is missing from your request."
                )

        if code is None:
            log.debug("code missing")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.missing',
                    message = "code is missing from your request."
                )

        if redirect_uri is None:
            log.debug("redirect_uri missing")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.missing',
                    message = "redirect_uri is missing from your request."
                )

        if client_id is None:
            log.debug("client_id missing")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.missing',
                    message = "client_id is missing from your request."
                )

        if grant_type != "authorization_code":
            log.debug("malformed grant_type")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.malformed',
                    message = "grant_type is malformed."
                )

        try:
            ar = OAuthenticationRequest.objects.get(code=code, redirect_uri=redirect_uri)
        except OAuthenticationRequest.DoesNotExist:
            log.debug("No ar")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.malformed',
                    message = "Access token not found, or incorrect redirect_uri."
                )

        print ar.application.id
        print client_id

        if str(ar.application.id) != client_id:
            log.debug("malformed client_id")
            response.status_int = 400
            return dict(
                    status = 'error',
                    code = 'argument.success.malformed',
                    message = "client_id is malformed."
                )

        print "HELLO"

        payload = dict(
            access_token=str(ar.grant.id),
            token_type="example",
            expires_in=ar.grant.expires.replace(tzinfo=None)-datetime.utcnow()
        )

        print redirect_uri

        return 'json:', dict(
            access_token=str(ar.grant.id),
            expires_in=(ar.grant.expires.replace(tzinfo=None)-datetime.utcnow()).seconds
        )

        print payload.get('access_token')
        print payload.get('expires_in')
        print redirect_uri

        requests.post(redirect_uri, data=payload)