#!/usr/bin/python

import logging
import string
from datetime import datetime
from google.appengine.ext import db

# ------------------------------------------------------------------------------
# oauth db entities
# ------------------------------------------------------------------------------

class OAuthRequestToken(db.Model):
    """OAuth Request Token."""

    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class OAuthAccessToken(db.Model):
    """OAuth Access Token."""

    specifier = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
