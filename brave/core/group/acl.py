# encoding: utf-8

from __future__ import unicode_literals

from datetime import datetime
from collections import OrderedDict
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentField, StringField, EmailField, URLField, DateTimeField, BooleanField, ReferenceField, ListField, IntField

from brave.core.util.signal import update_modified_timestamp

from brave.core.character.model import EVECharacter, EVECorporation, EVEAlliance

log = __import__('logging').getLogger(__name__)


class ACLRule(EmbeddedDocument):
    """The basic data structure and abstract API for ACL rules.
    
    See: https://github.com/bravecollective/core/wiki/Groups
    """
    
    meta = dict(
            abstract = True,
            allow_inheritance = True,
        )
    
    # ACL rules evaluate to None (doesn't apply), False (deny access), and True (allow access)
    # the fist ACLRule for a group that evaluates non-None is the accepted result
    grant = BooleanField(db_field='g', default=False)  # paranoid default
    inverse = BooleanField(db_field='z', default=False)  # pass/fail if the rule *doesn't* match
    
    def evaluate(self, user, character):
        raise NotImplementedError()
    
    def __repr__(self):
        return "{0}({1})".format(self.__class__.__name__, self)
    
    def __unicode__(self):
        return '{0} {1}'.format(
                'grant' if self.grant else 'deny',
                'if not' if self.inverse else 'if',
            )


class ACLList(ACLRule):
    """Grant or deny access based on the character's ID, corporation ID, or alliance ID."""
    
    KINDS = OrderedDict([
            ('c', "Character"),
            ('o', "Corporation"),
            ('a', "Alliance")
        ])
    KIND_CLS = OrderedDict([
            ('c', EVECharacter),
            ('o', EVECorporation),
            ('a', EVEAlliance)
        ])
    
    kind = StringField(db_field='k', choices=KINDS.items())
    ids = ListField(IntField(), db_field='i')
    
    def evaluate_character(self, user, character):
        return character.identifier in self.ids
    
    def evaluate_corporation(self, user, character):
        return character.corporation.identifier in self.ids
    
    def evaluate_alliance(self, user, character):
        return character.alliance and character.alliance.identifier in self.ids
    
    def evaluate(self, user, character):
        if getattr(self, 'evaluate_' + self.KINDS[self.kind].lower())(user, character):
            return None if self.inverse else self.grant
        
        # this acl rule doesn't match or is not applicable
        return self.grant if self.inverse else None
    
    def target_objects(self):
        return self.KIND_CLS[self.kind].objects(identifier__in=self.ids)
    
    def __repr__(self):
        return "ACLList({0} {1} {2} {3!r})".format(
                'grant' if self.grant else 'deny',
                'if not' if self.inverse else 'if',
                self.KINDS[self.kind],
                self.ids
            )

    def __unicode__(self):
        return "{grant} if character {is_}{prep} {set}".format(
                grant='grant' if self.grant else 'deny',
                is_='is not' if self.inverse else 'is',
                prep=' in' if self.kind != 'c' else '',
                set=' or '.join([o.name for o in self.target_objects()]),
            )


class ACLKey(ACLRule):
    """Grant or deny access based on the character's key type."""
    
    KINDS = OrderedDict([
            ('Account', "Account"),
            ('Character', "Character"),
            ('Corporation', "Corporation")
        ])
    
    kind = StringField(db_field='k', choices=KINDS.items())
    
    def evaluate(self, user, character):
        for key in character.credentials:
            if key.kind == self.kind:
                return None if self.inverse else self.grant
        
        return self.grant if self.inverse else None
    
    def __unicode__(self):
        return '{grant} if user {has} submitted a {kind} key'.format(
                grant='grant' if self.grant else 'deny',
                has='has not' if self.inverse else 'has',
                kind=self.KINDS[self.kind].lower()
        )


class ACLTitle(ACLRule):
    """Grant or deny access based on the character's corporate title."""
    
    titles = ListField(StringField(), db_field='t')
    
    def evaluate(self, user, character):
        if set(character.titles) & set(self.titles):
            return None if self.inverse else self.grant
        
        # this acl rule doesn't match or is not applicable
        return self.grant if self.inverse else None
    
    def __unicode__(self):
        return "{grant} if user {has} the corporate title {set}".format(
                grant='grant' if self.grant else 'deny',
                has="doesn't have" if self.inverse else 'has',
                set=' or '.join(self.titles),
        )


class ACLRole(ACLRule):
    """Grant or deny access based on the character's corporate role."""
    
    roles = ListField(StringField(), db_field='t')
    
    def evaluate(self, user, character):
        if set(character.roles) & set(self.roles):
            return None if self.inverse else self.grant
        
        # this acl rule doesn't match or is not applicable
        return self.grant if self.inverse else None
    
    def __unicode__(self):
        return "{grant} if user {has} the corporate role {set}".format(
                grant='grant' if self.grant else 'deny',
                has="doesn't have" if self.inverse else 'has',
                set=' or '.join(self.roles),
        )


class ACLMask(ACLRule):
    """Grant or deny access based on having a key capable of evaluating the given mask."""
    
    mask = IntField(db_field='m')
    
    def evaluate(self, user, character):
        mask = self.mask
        
        for cred in character.credentials:
            if cred.mask.has_access(mask):
                return None if self.inverse else self.grant
        
        return self.grant if self.inverse else None
    
    def __unicode__(self):
        return '{grant} if user {has} submitted a key supporting permissions {mask}'.format(
                grant='grant' if self.grant else 'deny',
                has='has not' if self.inverse else 'has',
                mask=self.mask,
        )


class ACLVerySecure(ACLRule):
    """Grant or deny access based on mandatory use of an OTP."""
    
    def evaluate(self, user, character):
        if user.otp_required:
            return None if self.inverse else self.grant
        
        return self.grant if self.inverse else None
    
    def __repr__(self):
        return "ACLVerySecure({0})".format(self.human_readable_repr())
    
    def __unicode__(self):
        # We usually call this __unicode__ in Python 2, __str__ in Python 3.  Then you can just
        # unicode(aclruleobj) to get the text version, and ${aclruleobj} will naturally work in templates
        # without extra function calls (since ${expr} automatically calls unicode(expr) anyway!)
        return '{0} {1} OTP mandatory for user'.format(
                'grant' if self.grant else 'deny',
                'if not' if self.inverse else 'if'
            )
