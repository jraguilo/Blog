import hashlib
import hmac
import random
import re

from datetime import datetime, timedelta
from google.appengine.api import memcache

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
    val, age = post_tuple
    if not val or update:
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