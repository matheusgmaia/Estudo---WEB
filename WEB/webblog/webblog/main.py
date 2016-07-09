import os
import webapp2
import jinja2
import json
import sys
import re
import random
import string
import hashlib
import hmac
import logging
import time

from google.appengine.api import memcache
from google.appengine.ext import db
from string import letters

import webapp2
import jinja2

SECRET = 'MUITOSECRETO'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    email = db.TextProperty(required = False)
    
class Post(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

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
    
def make_secure_val(valor):
    h = hmac.new(SECRET, valor).hexdigest()
    return '%s|%s' % (valor, h)

def valid_secure_val(secure_valor):
    valor = secure_valor.split("|")[0]
    if secure_valor == make_secure_val(valor):
        return valor
    
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
    
class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def set_secure_cookie(self, nome, valor):
        cookie_val = make_secure_val(valor)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'%(nome, str(cookie_val)))
        
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and valid_secure_val(cookie_val)

###Sing-up Log-in Welcome###

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.email = ''
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
            self.pw_hash = make_pw_hash(self.username, self.password)
            u = User(username = self.username, password = self.pw_hash, email = self.email)
            u.put()
            self.set_secure_cookie('user_id', str(u.key().id()))
            self.redirect('/welcome')
            
class Login(BaseHandler):
    def get(self):
        self.render("loginpost.html")
        
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        have_error = False
        
        params = dict(username = self.username)
                      
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        if have_error:
            self.render('loginpost.html', **params)
        else:
            u = User.all().filter('username =', self.username).get()
            if u:
                self.set_secure_cookie('user_id', str(u.key().id()))
                self.redirect('/welcome')
            else:
                params['error_password'] = "Voce n esta cadastrado"
                self.render('loginpost.html', **params)
            
class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')   
        
class Welcome(BaseHandler):
    def get(self):
        uid = self.read_secure_cookie('user_id')
        user = uid and User.get_by_id(int(uid))
        if user:
            self.render('welcome.html', username = user.username)
        else:
            self.redirect('/signup')
      
### BLOG DO PALAVRAO ###
start_time = None
def top_posts(update = False):
        key = 'top'
        posts = memcache.get(key)
        if posts is None or update:
                logging.error("DB QUERY")
                posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
                posts = list(posts)
                memcache.set(key, posts)
                global start_time
                start_time = time.time()
        return posts
        

            

class BlogHandler(BaseHandler):
    def get(self):
       # global start_time
       # start_time = time.time()
        posts = top_posts()
        if start_time != None:
            QUERIED = ("Queried %i seconds ago") % (time.time() - start_time)
        else:
            QUERIED = "Queried %i seconds ago" % 0
        self.render("blog.html", posts = posts, QUERIED = QUERIED)
        
class BlogJson(BaseHandler):
    def get(self):
        self.response.headers["Content-Type"] = "application/json"
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        posts = list(posts)
        a = ",".join(json.dumps({"content":  post.body, "subject": post.title})for post in posts)
        a = "["+a+"]"
        self.write(a)

class NewPost(BaseHandler):
    def render_post(self, title = "", body = "", error = ""):
        self.render("front.html", title = title, body = body, error = error)
    
    def get(self):
        self.render("front.html")
    
    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")
        
        if title and body:
            a = Post(title = title, body = body)
            a.put()
            self.redirect("/%s" % str(a.key().id()))
            top_posts(True)
            memcache.set(str(a.key().id()), (a, time.time()))
        else:
            error = "Precisamos de ambos nome e palavrao"
            self.render_post(title, body, error)
        
class PostHandler(BaseHandler):
    def get(self, post_id):
        post, timee = memcache.get(post_id)
        if not post:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
        title = post.title
        body = post.body
        QUERIED = ("Queried %i seconds ago") % (time.time() - timee)
        self.render("post.html", body = body, title = title, QUERIED = QUERIED)
        
        
class PermaJson(BaseHandler):
    def get(self, post_id):
        self.response.headers["Content-Type"] = "application/json"
        title = Post.get_by_id(int(post_id)).title
        body = Post.get_by_id(int(post_id)).body
        a = "".join(json.dumps({"content":  body, "subject": title}))
        a = "["+a+"]"
        self.write(a)
        
class Flush(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')
app = webapp2.WSGIApplication([('/', BlogHandler),
                                ('/newpost', NewPost),
                                ('/signup', Signup),
                                ('/login', Login),
                                ('/logout', Logout),
                                ('/welcome', Welcome),
                                ('/([0-9]+)', PostHandler),
                                ('/.json', BlogJson),
                                ('/([0-9]+).json', PermaJson),
                                ('/flush', Flush)],
                                debug=True)