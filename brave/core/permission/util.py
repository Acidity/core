# encoding: utf-8

from __future__ import unicode_literals

from datetime import datetime
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField

from brave.core.util.signal import update_modified_timestamp
from brave.core.permission.model import Permission, WildcardPermission, GRANT_WILDCARD
from brave.core.account.model import User
from web.core.http import HTTPForbidden, HTTPUnauthorized
import web.auth


log = __import__('logging').getLogger(__name__)


def user_has_permission(perm=None):
    
    def decorator(function):
        
        def check_permission(self, *args, **kwargs):
            user = web.auth.user
            
            # If there is no user, they don't have permission
            if not user or not user._current_obj():
                log.debug('user not a valid object')
                raise HTTPUnauthorized()
        
            # If there is no permission provided, then any auth'd user has permission
            if not perm:
                log.debug('No permission provided.')
                return function(self, *args, **kwargs)
            #elif not perm:
            #   perm_string = function.__module__[6:] + '.' + str(self.__class__.__name__) + '.' + function.func_name
            #    log.debug("Using autogenerated permission: {0}".format(perm_string))
            #    permission = perm_string
            else:
                permission = perm
        
            user = user._current_obj()
        
            # No user with that username was found.
            if not len(user):
                log.debug('User not found in database.')
                raise HTTPForbidden()
        
            user = user.first()
            
            # User has no characters, so they have no permissions.
            if not len(user.characters):
                log.debug('User has no characters.')
                raise HTTPForbidden()
            
            # Cycle through the user's permissions, and if they have it leave the method.
            for c in user.characters:
                if c.has_permission(permission):
                    return function(self, *args, **kwargs)
            
            # User doesn't have this permission, so we raise HTTPForbidden
            log.debug('User has no characters with that permission.')
            raise HTTPForbidden()
            
        return check_permission
    
    return decorator
