import os
import re
import random
import string
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = 'MUITOSECRETO'

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    email = db.TextProperty(required = False)

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
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def set_secure_cookie(self, nome, valor):
        cookie_val = make_secure_val(valor)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'%(nome, str(cookie_val)))
        
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and valid_secure_val(cookie_val)

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
            #user = User.all().filter('username =', username).get()
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
    #    h = self.request.cookies.get('useer_id')
     #   self.response.out.write(h)
     #   username =  User_id.all().filter('userid =', h).get().username
     #   salt =  User_id.all().filter('userid =', h).get().salt
     #  if (h == hashlib.sha256(SECRET + username + salt).hexdigest()):
      #      self.render('welcome.html', username = username)
      #  else:
       #     self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)],
                              debug=True)
