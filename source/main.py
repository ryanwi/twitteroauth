#!/usr/bin/python
#
# This is a sample App Engine app for utilizing the Twitter API with OAuth
#
# This particular app is a derivative of the tweetapp framework by tav@espians.com available at:
# http://github.com/tav/tweetapp/tree/master
#

"""The main application file for handling app engine requests"""

import os
import cgi
import logging
import uuid
import wsgiref.handlers

from datetime import datetime, timedelta
from uuid import uuid4

from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.api import urlfetch
from google.appengine.ext.webapp import template
from django.template import TemplateDoesNotExist

import oauth
import datamodel

# Set to true if we want to have our webapp print stack traces, etc
_DEBUG = True    

OAUTH_APP_SETTINGS = {
        'consumer_key': '',
        'consumer_secret': '',
        'request_token_url': 'https://twitter.com/oauth/request_token',
        'access_token_url': 'https://twitter.com/oauth/access_token',
        'user_auth_url': 'http://twitter.com/oauth/authorize',
        'default_api_prefix': 'http://twitter.com',
        'default_api_suffix': '.json',
        'oauth_callback': None,
        }
CLEANUP_BATCH_SIZE = 100
EXPIRATION_WINDOW = timedelta(seconds=60*60*1) # 1 hour

        
class BaseHandler(webapp.RequestHandler):
    """Supplies a common template generation function.

    When you call generate(), we augment the template variables supplied with
    the current user in the 'user' variable and the current webapp request
    in the 'request' variable.
    """
    def generate(self, template_name, template_values={}):
        
        values = {
            'request': self.request,
            'host': self.request.host,
            'debug': self.request.get('debug'),
            'application_name': 'TwitterOAuth',
        }
        
        values.update(template_values)
        directory = os.path.dirname(__file__)
        path = os.path.join(directory, os.path.join('templates', template_name))
            
        try:
            self.response.out.write(template.render(path, values, debug=_DEBUG))
        except TemplateDoesNotExist, e:
            self.response.headers["Content-Type"] = "text/html; charset=utf-8"
            self.response.set_status(404)
            self.response.out.write(template.render(os.path.join('templates', '404.html'), values, debug=_DEBUG))
        
    def error(self, status_code):
        webapp.RequestHandler.error(self, status_code)
        if status_code == 404:
            self.generate('404.html')

    def get_cookie(self, name):
        return self.request.cookies.get(name)

    def set_cookie(self, name, value, path='/', expires="Fri, 31-Dec-2021 23:59:59 GMT"):
        self.response.headers.add_header(
            'Set-Cookie', 
            '%s=%s; path=%s; expires=%s' % (name, value, path, expires))

    def expire_cookie(self, name, path='/'):
        self.response.headers.add_header(
            'Set-Cookie', 
            '%s=; path=%s; expires="Fri, 31-Dec-1999 23:59:59 GMT"' %
            (name, path)
            )
        
    def create_uuid(self):
        return 'id-%s' % uuid4().hex


class MainPageHandler(BaseHandler):
    def get(self):
    
        key_name = self.get_cookie('oauth')
        
        if key_name is None:
            values = {
                'is_user_logged_in':False,
            }
        else:
            access_token = datamodel.OAuthAccessToken.get_by_key_name(key_name)
            oauth_token = oauth.OAuthToken(access_token.oauth_token, access_token.oauth_token_secret)
            client = oauth.OAuthClient(self, OAUTH_APP_SETTINGS, oauth_token)

            #info = client.get('/account/verify_credentials')
            #rate_info = client.get('/account/rate_limit_status')
            friends_timeline = client.get('/statuses/friends_timeline')
            values = {
                'is_user_logged_in':True,
            #    'info':info,
            #    'rate_info':rate_info,
                'screen_name':access_token.specifier,
                'timeline':friends_timeline
            }
            
        self.generate('index.html', values)

        
class StatusUpdateHandler(BaseHandler):        
    def post(self):
        status = cgi.escape(self.request.get('status'))
        
        key_name = self.get_cookie('oauth')
        access_token = datamodel.OAuthAccessToken.get_by_key_name(key_name)
        oauth_token = oauth.OAuthToken(access_token.oauth_token, access_token.oauth_token_secret)
        client = oauth.OAuthClient(self, OAUTH_APP_SETTINGS, oauth_token)

        status = client.post('/statuses/update', status=status)
        logging.debug(status)
        self.redirect('/')
        
        
class TwitterOAuthHandler(BaseHandler):
    '''Request Handler for all OAuth workflow when authenticating user'''

    def get(self, action=''):
        self._client = oauth.OAuthClient(self, OAUTH_APP_SETTINGS)
        
        if action == 'login':
            self.login()
        elif action == 'logout':
            self.logout()
        elif action == 'callback':
            self.callback()
        elif action == 'cleanup':
            self.cleanup()

    def login(self):
        # get a request token
        raw_request_token = self._client.get_request_token()

        # store the request token
        request_token = datamodel.OAuthRequestToken(
            oauth_token=raw_request_token.key,
            oauth_token_secret=raw_request_token.secret,
            )
        request_token.put()

        # get the authorize url and redirect to twitter
        authorize_url = self._client.get_authorize_url(raw_request_token)
        self.redirect(authorize_url)

    def logout(self):    
        self.expire_cookie('oauth')
        self.redirect('/')

    def callback(self):
        # lookup request token
        raw_oauth_token = self.request.get('oauth_token')
        logging.debug(raw_oauth_token)
        request_token = datamodel.OAuthRequestToken.all().filter(
            'oauth_token =', raw_oauth_token).fetch(1)[0]

        # get an access token for the authorized user
        oauth_token = oauth.OAuthToken(request_token.oauth_token, request_token.oauth_token_secret)
        raw_access_token = self._client.get_access_token(oauth_token)
        
        # get the screen_name
        self._client = oauth.OAuthClient(self, OAUTH_APP_SETTINGS, raw_access_token)
        screen_name = self._client.get('/account/verify_credentials')['screen_name']

        # delete any old access tokens for this user
        old = datamodel.OAuthAccessToken.all().filter('specifier =', screen_name)
        db.delete(old)
        
        # store access token
        key_name = self.create_uuid()
        access_token = datamodel.OAuthAccessToken(
            key_name=key_name,
            specifier=screen_name,
            oauth_token=raw_access_token.key,
            oauth_token_secret=raw_access_token.secret,
            )
        access_token.put()
        
        self.set_cookie('oauth', key_name)
        self.redirect('/')
        
    def cleanup(self):
        query = datamodel.OAuthRequestToken.all().filter(
            'created <', datetime.now() - EXPIRATION_WINDOW
            )
        count = query.count(CLEANUP_BATCH_SIZE)
        db.delete(query.fetch(CLEANUP_BATCH_SIZE))
        self.response.out.write("Cleaned %i entries" % count)


def main():
    logging.getLogger().setLevel(logging.DEBUG)
    application = webapp.WSGIApplication(
                                        [('/', MainPageHandler),
                                        ('/oauth/twitter/(.*)', TwitterOAuthHandler),
                                        ('/status/update', StatusUpdateHandler)],
                                        debug=_DEBUG)
    wsgiref.handlers.CGIHandler().run(application)

if __name__ == "__main__":
    main()
