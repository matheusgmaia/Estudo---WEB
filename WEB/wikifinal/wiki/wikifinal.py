import webapp2
import os
import re
import random
import hashlib
import hmac
import logging
import json
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
                               
secret = 'MDSQUESENHASECRETA'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
   
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

            
###SINGUP LOGIN SINGOUT####
            
            
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(MainHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError            

class Register(Signup):         
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(MainHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

        
###  WIKI  ###
class Wiki(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    version = db.IntegerProperty(required = True)
    
class MainPage(MainHandler):
    def get(self):
        try:
            w = Wiki.all().filter("name =", "/home").order("-created")[0]
            content = w.content
        except IndexError:
            content = ""
        self.render("pageedited.html", content = content)        
    
class WikiPage(MainHandler):
    def get(self, page):
        versao = self.request.get("v")
        if versao:
            p = Wiki.all().filter('name =', str(page)).filter('version =', int(version)).get()
        else:
            versao = 0
            p = Wiki.all().filter('name =', str(page)).get()
        if p:
           self.render("pageedited.html", content = p.content)
        else:
            self.redirect('/_edit' + page)


        
class EditPage(MainHandler):
    def get(self, page):
        if not self.user:
            self.redirect('/login')
        edit = ""
        p = Wiki.all().filter('name =', page).order('-created').get()
        if p:
            edit = p.content
        self.render("editpage.html", page = page)
    def post(self, page):
        if self.user:
            content = self.request.get('content')
            if content:
                home = False
                if page == "/":
                    home = True
                    page = "/home"
                try:
                    pages = Wiki.all().filter("name =", page)
                    wikis = list(pages)
                    version = len(wikis) + 1
                except IndexError:
                    version = 1
                p = Wiki(name = page, content = content, version = version)
                p.put()
                self.response.headers['Content-Type'] = 'text/html; charset=utf-8.'
                time.sleep(4)
                if home:
                    self.redirect('/')
                else:
                    self.redirect('%s' % page)
            else:
                self.redirect('/_edit' + page)
        
class HistoryPage(MainHandler):
    def get(self, page):
        wikis = Wiki.all().filter("name =", page).order("-created")
        self.render("show_history.html", wiki_url = page, wikis = wikis)
        
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)