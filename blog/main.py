import json
import os
from string import letters

import webapp2
import handlers
import utils


from google.appengine.ext import db

                               
SECRET = '89uij7se'   

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
    email = db.StringProperty(required = False)
    
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

class MainPage(handlers.BlogHandler):
    def get(self):
        post_tuple = utils.post_cache('front')
        posts, age = post_tuple
        if self.format == 'html':
            self.render("front.html", posts=posts, age=utils.age_str(age))
        else:
            post_list = []
            for post in posts:
                post_list.append(post.as_dict())
            self.render_json(post_list)
        
#Handler for creating new blog posts
class PostHandler(handlers.BlogHandler):
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
            utils.post_cache('front', True)
            print str(p.key())
            utils.post_cache(str(p.key()), True)
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Missing subject or content"
            self.render_front(subject, content, error)

#Handler for displaying individual blog posts            
class PostPage(handlers.BlogHandler):
    def get(self, post_id):
        post, age = get_age(post_id)
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            utils.set_age(post_id, post)
            age = 0
        if not post:
            self.error(404)
            return
            
        if self.format == 'html':
            self.render("permalink.html", post = post, age = utils.age_str(age))
        else:
            self.render_json(post.as_dict())

class Register(handlers.BlogHandler):
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
            
        if error:
            #render registration page with error messages
            self.render("register.html", **params)
        else:
            #create user
            u = User.register(username, password, email)
            u.put()
            self.login(u)
            self.redirect('/welcome?username=' + username)
            
class Login(handlers.BlogHandler):
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
    
class Logout(handlers.BlogHandler):
    def get(self):
        self.logout()
        self.render("login.html")
        
class FlushCache(handlers.BlogHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')
        
class WelcomePage(handlers.BlogHandler):
    def get(self):
        username = self.request.get('username')
        self.render("welcome.html", username = username)
        

app = webapp2.WSGIApplication([
    ('/?(?:\.json)?', MainPage),
    ('/newpost', PostHandler),
    ('/([0-9]+)(?:\.json)?', PostPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/flush', FlushCache),
    ('/welcome', WelcomePage)
], debug=True)
