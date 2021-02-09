# two_factor_auth
This module is for Odoo version 8.0 and has enabled two factor authentication using Google

### Controllers:
This takes care of navigating login page to home page.

```class Home(openerp.addons.web.controllers.main.Home):

    @http.route('/web/login', type='http', auth="none")
    def web_login(self, redirect=None, **kw):
        openerp.addons.web.controllers.main.ensure_db()
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)
.
.
```
Above code is present in default module but its been overwritten to navigate to two factor authentication screen. Once, username, password and unique code 
has been verified user will be directed to the home page. 

### static
This directory contains all the view related changes which makes sure about the look and feel of the new page.

### __init__.py
Python files which needs to be part of the module, needs to be included in this file

### __openerp__.py
xml files which needs to be part of the module, needs to be included in this file. Along with that, it takes care of dependency on other modules.

### res_users.py
The file has all the backed logic for sending URL to the user via email to first setup two factor authentication on his/her mobile device. Also, once user
enters authentication code, it will be verified using following function.
```
    def authenticate_secret_key(self, db, login, token, user_agent_env):
        """ Template calls this function to verify entered secret key or OTP"""
        authenticated = self.authenticate_user(db, login, token)
        return authenticated  
```
### res_users.xml
The file has backend view related changes such as button to send secret to user via email. The secret which is sent to user will also be store on the database so that we can generate unique code
on our end to validate the user entered authentication code. 