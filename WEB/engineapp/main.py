#!/usr/bin/env python
# -*- coding: cp1252 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re
form = """
<form method="post">
    <b>Enter some text to ROT13:</b>
    <br>
    <textarea name="text" style="height: 100px; width: 400px; type="text">%(texto)s</textarea>
    <br>
    <input type="submit">
</form>
"""
class RotHandler(webapp2.RequestHandler):
    def write_form(self, texto=""):
        self.response.write(form %{"texto":texto})
        
    def get(self):
        self.write_form()
        
    def post(self):
        texto = self.request.get('text')
        cypher = ''
        alphabet = list('abcdefghijklmnopqrstuvwxyz')
        alphabet2 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        pontuation = list("!?<>\'")
        for b in texto:
            c = cgi.escape(b, quote = True)
            if c in alphabet2:
                cypher += alphabet2[(alphabet2.index(c)+13)%(len(alphabet2))]
            elif c in alphabet:
                cypher += alphabet[(alphabet.index(c)+13)%(len(alphabet))]
            else:
                cypher += c
        self.write_form(cypher)

form2 = """
<form method="post">
<h2>Singup</h2>
<br><br>
<table>
<tr>
<label>
<td>
Username
</td>
<td>
    <input name="user_name" value="%(name)s">
    <div style="color: red">%(errorN)s</div>
</label>
</td>
</tr>
<label>
Password
    <input type= "password" name="user_password">
    <div style="color: red">%(errorP)s</div>
</label>

<label>
Verify Password
    <input type="password" name="user_verify">
    <div style="color: red">%(errorVP)s</div>
</label>
<tr>
<label>
<td>
Email
</tr>
<td>
    <input name="user_email" value="%(email)s">
    <div style="color: red">%(errorE)s</div>
</label>
</td>
</tr>
</table>
<br>
<input type="submit">
</form>
"""
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    def valid_username(username):
        return username and USER_RE.match(username)
    
    PASS_RE = re.compile(r"^.{3,20}$")
    def valid_pass(password):
        return password and PASS_RE.match(password)

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_email(email):
        return email or EMAIL_RE.match(email)

class EmailHandler(webapp2.RequestHandler):

    def valid_vpass(password, vpassword):
        if(password == vpassword):
            return True
        else:
            return False    
    
    def writeform(self, name='', errorN='', errorP='', errorVP='', email='', errorE=''):
        self.response.write(form2 %{"name":name, "errorN":errorN, "errorP": errorP,"errorVP":errorVP, "email":email, "errorE":errorE})

    def get(self):
        self.writeform()
        
    def post(self):
        
        username = self.request.get('user_name')
        password = self.request.get('user_password')
        verify = self.request.get('user_verify')
        email = self.request.get('user_email')
        
        validaN = valid_username(username);
        validaP = valid_pass(password);
        validaVP = valid_vpass(password, vpassword);
        validaE = valid_email(email);

        error = False

        if not validaN:
            error = True

        if not validaP:
            error=True
        elif not validaVP:
            error=True

        if not validaE:
            error=True

        if error=True:
            this.writeform()

        else:
            self.redirect('/welcome?username=' + username)

app = webapp2.WSGIApplication([('/', RotHandler),
                               ('/email', EmailHandler)
                               ('/welcome', Welcome)], debug=True)
