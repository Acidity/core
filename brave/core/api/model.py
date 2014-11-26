# encoding: utf-8

from __future__ import unicode_literals

from datetime import datetime, timedelta
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField
import random
from brave.core.util.signal import update_modified_timestamp
from brave.core.application.signal import trigger_private_key_generation
from brave.core.util.field import PasswordField, IPAddressField


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

class OAuthenticationRequest(Document):
    meta = dict(
            allow_inheritance = False,
            indexes = [
                    dict(fields=['expires'], expireAfterSeconds=0),
                    'code'
                ]
        )

    application = ReferenceField('Application', db_field='a')
    user = ReferenceField('User', db_field='u')
    grant = ReferenceField('ApplicationGrant', db_field='g')
    scope = StringField(db_field='s')
    state = StringField(db_field='t')

    code = StringField()

    redirect_uri = URLField(db_field='r')

    expires = DateTimeField(db_field='e', default=lambda: datetime.utcnow() + timedelta(minutes=10))

    def clean(self):
        if not self.code:
            self.code = ''.join([random.choice("abcdef0123456789") for x in range(0, 16)])

    def __repr__(self):
        return 'AuthenticationRequest({0}, {1}, {2}, {3})'.format(self.id, self.application, self.user, self.grant)
