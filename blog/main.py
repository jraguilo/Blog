import hashlib
import hmac
import json
import random
import re
import os
from datetime import datetime, timedelta
from string import letters

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
                               
SECRET = '89uij7se'  

#validation functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
    
PASS_RE = re.compile(r"^.{1,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):            
    return email and EMAIL_RE.match(email)
    
#user functions
#Note: Password hashing is self implemented for learning purposes only
def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))
    
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, hash)

def valid_pw(name, pw, hash):
    salt = hash.split(',')[0]
    return hash == make_pw_hash(name, pw, salt)
    
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())
    
def check_secure_val(hash):
    val = hash.split('|')[0]
    if hash == make_secure_val(val):
        return val

def user_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)
    
def post_cache(key, update = False):
    post_tuple = get_age(key)
    if post_tuple is None or update:
        val = db.GqlQuery("SELECT * FROM Post ORDER BY last_modified DESC")
        val = list(val)
        set_age(key, val)
        post_tuple = get_age(key)
    return post_tuple
    
def set_age(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))
    
def get_age(key):
    val_tuple = memcache.get(key)
    if val_tuple:
        val, save_time = val_tuple
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0
    return val, age
    
def age_str(age):
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age
        
        
class BlogHandler(webapp2.RequestHandler):
    #For reference, *a is arguments, *kw is dictionary
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
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
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.by_id(int(user_id))
        
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

#create database for blog posts        
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    def as_dict(self):
        time_format = '%c'
        post_dict = {'subject' : self.subject,
                'content' : self.content,
                'created' : self.created.strftime(time_format),
                'last_modified' : self.last_modified.strftime(time_format)}
        return post_dict
    
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = user_key())
    
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u
        
    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = user_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
                    
    @classmethod
    def authenticate_user(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
            
#Handler for front page
class MainHandler(BlogHandler):
    def get(self):
        post_tuple = post_cache('front')
        posts, age = post_tuple
        if self.format == 'html':
            self.render("front.html", posts=posts, age = age_str(age))
        else:
            post_list = []
            for post in posts:
                post_list.append(post.as_dict())
            self.render_json(post_list)
        
#Handler for creating new blog posts
class PostHandler(BlogHandler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
        
    def get(self):
        self.render_front()
        
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            p = Post(parent = blog_key(), subject=subject, content=content)
            p.put()
            post_cache('front', True)
            print str(p.key())
            post_cache(str(p.key()), True)
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Missing subject or content"
            self.render_front(subject, content, error)

#Handler for displaying individual blog posts            
class PostPage(BlogHandler):
    def get(self, post_id):
        post, age = get_age(post_id)
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            set_age(post_id, post)
            age = 0
        if not post:
            self.error(404)
            return
            
        if self.format == 'html':
            self.render("permalink.html", post = post, age = age_str(age))
        else:
            self.render_json(post.as_dict())

class Register(BlogHandler):
    def get(self):
        self.render("register.html")
        
    def post(self):
        #get input
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
       
        error = False
        params = dict(username = username, email = email)
       
        #verify input
        if not valid_username(username):
            params['user_error'] = "That was not a valid username"
            error = True
            
        else:
            #make sure the user does not already exist
            u = User.by_name(username)
            if u:
                params['user_error'] = "That user already exists"
                error = True
        if not valid_password(password):
            params['pass_error'] = "That was not a valid password"
            error = True
        elif password != verify:
            params['verify_error'] = "Your passwords did not match"
        if not valid_email(email):
            params['email_error'] = "That was not a valid email"
            error = True
            
        if error:
            #render registration page with error messages
            self.render("register.html", **params)
        else:
            #create user
            u = User.register(username, password, email)
            u.put()
            self.login(u)
            self.redirect('/welcome?username=' + username)
            
class Login(BlogHandler):
    def get(self):
        self.render("login.html")
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        #verify username and password
        u = User.authenticate_user(username, password)
        if u:
            self.login(u)
            self.write("login successful")
        else:
            msg = "Invalid Login"
            self.render("login.html", error = msg)
    
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.render("login.html")
        
class WelcomePage(BlogHandler):
    def get(self):
        username = self.request.get('username')
        self.write("Welcome %s" % username)
        

app = webapp2.WSGIApplication([
    ('/?(?:\.json)?', MainHandler),
    ('/newpost', PostHandler),
    ('/([0-9]+)(?:\.json)?', PostPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', WelcomePage)
], debug=True)
