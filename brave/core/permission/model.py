# encoding: utf-8

from __future__ import unicode_literals

from datetime import datetime
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField

from brave.core.util.signal import update_modified_timestamp


log = __import__('logging').getLogger(__name__)

GRANT_WILDCARD = '*'


class Permission(Document):
    meta = dict(
        collection='Permissions',
        allow_inheritance = True,
        indexes = [
            dict(fields=['name'], unique=True, required=True)
        ],
    )
    
    name = StringField(db_field='n')
    description = StringField(db_field='d')
    
    @property
    def application(self):
        """Returns the application that this permission is for."""
        
        from brave.core.application.model import Application
        
        # Handle '*' properly
        if self.name.find('.') == -1:
            return None
        
        app_short = self.name.split('.')[0]
        
        app = Application.objects(short=app_short)
        
        if not len(app):
            return None
        else:
            return app.first()
            
    def __repr__(self):
        return "Permission('{0}')".format(self.name)
            
    def getPermissions(self):
        """Returns all permissions granted by this Permission."""
        
        return set({self})
        
    def grantsPermission(self, perm_string):
        """This is used to see if a Permission grants access to a permission which is not in the database.
            For instance, when evaluating whether a WildcardPermission grants access to a run-time permission."""
        
        return(self.name == perm_string)
        
    def __eq__(self, other):
        if isinstance(other, Permission):
            return self.name == other.name
        return False
        
    def __ne__(self, other):
        return not self.__eq__(other)
        
class WildcardPermission(Permission):
    
    def __repr__(self):
        return "WildcardPermission('{0}')".format(self.name)
            
    def getPermissions(self):
        """Returns all Permissions granted by this Permission"""
        
        from brave.core.application.model import Application
        
        # Mongoengine has no way to find objects based on a regex (as far as I can tell at least...)
        perms = set()

        # Loops through all of the permissions, checking if this permission grants access to that permission.
        for perm in Permission.objects():
            if self.grantsPermission(perm.name):
                perms.add(perm)
        
        return perms
        
    def grantsPermission(self, perm_string):
        """This is used to see if a Permission grants access to a permission which is not in the database.
            For instance, when evaluating whether a WildcardPermission grants access to a run-time permission."""
        # Splits both this permission's name and the permission being checked.
        self_segments = self.name.split('.')
        perm_segments = perm_string.split('.')
        
        # If this permission has more segments than the permission we're matching against, it can't provide access
        # to that permission.
        if len(self_segments) > len(perm_segments):
            return False
        
        # If the permission we're checking against is longer than the wildcard permission (this permission), then this
        # permission must end in a wildcard for it to grant the checked permission.
        if len(self_segments) < len(perm_segments):
            if GRANT_WILDCARD != self_segments[-1]:
                return False
        
        # Loops through each segment of the wildcardPerm and permission name. 'core.example.*.test.*' would have 
        # segments of 'core', 'example', '*', 'test', and '*' in that order.
        for (s_seg, perm_seg) in zip(self_segments, perm_segments):
            # We loop through looking for something wrong, if there's nothing wrong then we return True.
            
            # This index is a wildcard, so we skip checks
            if s_seg == GRANT_WILDCARD:
                continue
            
            # If this self segment doesn't match the corresponding segment in the permission, this permission
            # doesn't match, and we return False
            if s_seg != perm_seg:
                return False
        
        return True
