# -*- coding: utf-8 -*-

import openerp.addons.web.http as http
from openerp.http import request
import openerp
from openerp import fields, http, registry, SUPERUSER_ID
from openerp.addons.web.controllers.main import Home, ensure_db
import logging
_logger = logging.getLogger(__name__)


class Tfa(http.Controller):

    @http.route('/web/tauth_login', type='http', auth="none")
    def tauth_login(self, redirect=None, **kw):
        if not redirect:
            redirect = '/web/tauth_login?' + request.httprequest.query_string
        return request.render("two_factor_auth.tauth_login")

    @http.route('/web/tauth_login/verify', type='http', auth="none", website=True)
    def verify(self, redirect=None, **kw):
        values = request.params.copy()
        if not redirect:
            redirect = '/web/?' + request.httprequest.query_string
        if not request.uid:
            request.uid = 3
        # Need to check the authenticate with google
        request.session.db = request.registry.get('res.users').decryption(values['f1'], values['l1'])
        request.params['login'] = request.registry.get('res.users').decryption(values['f2'], values['l2'])
        request.params['password'] = request.registry.get('res.users').decryption(values['f3'], values['l3'])
        if request.params.get('lost_mobile', False):
            request.registry.get('res.users').lost_mobile(
                request.session.db, request.params['login'])
            values['message'] = "OTP has been sent on registered Email ID"
            del values['lost_mobile']
            return request.render("two_factor_auth.tauth_login", values)
        else:
            # auth_brute_force code
            google_auth = False
            uid = False
            module_obj = registry(request.session.db)['ir.module.module']
            cr = module_obj.pool.cursor()
            auth_brute_module_id = module_obj.search(cr, SUPERUSER_ID, [('name', '=', 'auth_brute_force'),
                                                                        ('state', '=', 'installed')])
            cr.close()
            if len(auth_brute_module_id):
                environ = request.httprequest.environ
                remote = environ.get(
                    'HTTP_CF_CONNECTING_IP',
                    environ.get(
                        'HTTP_X_REAL_IP',
                        environ.get(
                            'HTTP_X_FORWARDED_FOR',
                            environ['REMOTE_ADDR'])))

                # Get registry and cursor
                config_obj = registry(request.session.db)['ir.config_parameter']
                attempt_obj = registry(
                    request.session.db)['res.authentication.attempt']
                banned_remote_obj = registry(
                    request.session.db)['res.banned.remote']
                cursor = attempt_obj.pool.cursor()

                # Get Settings
                max_attempts_qty = int(config_obj.search_read(
                    cursor, SUPERUSER_ID,
                    [('key', '=', 'auth_brute_force.max_attempt_qty')],
                    ['value'])[0]['value'])

                # Test if remote user is banned
                banned = banned_remote_obj.search(cursor, SUPERUSER_ID, [
                    ('remote', '=', remote)])
                if banned:
                    _logger.warning(
                        "Authentication tried from remote '%s'. The request has"
                        " been ignored because the remote has been banned after"
                        " %d attempts without success. Login tried : '%s'." % (
                            remote, max_attempts_qty, request.params['login']))
                    request.params['password'] = ''
                else:
                    # Try authentication with Google
                    google_auth = request.registry.get('res.users').authenticate_secret_key(
                        request.session.db, request.params['login'], request.params['unique_code'], False)
                    # Try to authenticate with credentials
                    if google_auth:
                        uid = request.session.authenticate(
                            request.session.db, request.params['login'],
                            request.params['password'])
                # Log attempt
                cursor.commit()
                attempt_obj.create(cursor, SUPERUSER_ID, {
                    'attempt_date': fields.Datetime.now(),
                    'login': request.params['login'],
                    'remote': remote,
                    'result': banned and 'banned' or (
                        (uid and google_auth) and 'successfull' or 'failed'),
                })
                cursor.commit()
                if not banned and not uid:
                    # Get last bad attempts quantity
                    attempts_qty = len(attempt_obj.search_last_failed(
                        cursor, SUPERUSER_ID, remote))

                    if max_attempts_qty <= attempts_qty:
                        # We ban the remote
                        _logger.warning(
                            "Authentication failed from remote '%s'. "
                            "The remote has been banned. Login tried : '%s'." % (
                                remote, request.params['login']))
                        banned_remote_obj.create(cursor, SUPERUSER_ID, {
                            'remote': remote,
                            'ban_date': fields.Datetime.now(),
                        })
                        cursor.commit()

                    else:
                        _logger.warning(
                            "Authentication failed from remote '%s'."
                            " Login tried : '%s'. Attempt %d / %d." % (
                                remote, request.params['login'], attempts_qty,
                                max_attempts_qty))
                cursor.close()
            # auth_brute_force code ends
            else:
                google_auth = request.registry.get('res.users').authenticate_secret_key(
                                    request.session.db, request.params['login'], request.params['unique_code'], False)
                if google_auth:
                    uid = request.session.authenticate(request.session.db, request.params[
                        'login'], request.params['password'])
            if google_auth and uid:
                return http.redirect_with_hash(redirect)
            elif not google_auth or not uid:
                values['error'] = "Wrong login/password or Incorrect Secret Key"
            if not request.uid:
                request.uid = 3
        del values['f1']
        del values['f2']
        del values['f3']
        del values['redirect']
        del values['unique_code']
        del values['l1']
        del values['l2']
        del values['l3']
        return request.render("web.login", values)


class Home(openerp.addons.web.controllers.main.Home):

    @http.route('/web/login', type='http', auth="none")
    def web_login(self, redirect=None, **kw):
        openerp.addons.web.controllers.main.ensure_db()
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)

        if not request.uid:
            request.uid = 3
        values = request.params.copy()
        if not redirect:
            redirect = '/web?' + request.httprequest.query_string
        values['redirect'] = redirect

        try:
            values['databases'] = http.db_list()
        except openerp.exceptions.AccessDenied:
            values['databases'] = None

        if request.httprequest.method == 'POST':
            old_uid = request.uid
            if request.registry.get('res.users').two_factor_enabled(request.session.db, request.params['login']):
                redirect = "two_factor_auth.tauth_login"
                db_enrypted = request.registry.get('res.users').encyption(request.session.db)
                login_enrypted = request.registry.get('res.users').encyption(request.params['login'])
                pwd_enrypted = request.registry.get('res.users').encyption(request.params['password'])
                tauth_values = {'f1': db_enrypted,
                                'f2': login_enrypted,
                                'f3': pwd_enrypted,
                                'l1': len(request.session.db),
                                'l2': len(request.params['login']),
                                'l3': len(request.params['password'])
                                }
                return request.render(redirect, tauth_values)

            # auth_brute_force code
            uid = False
            module_obj = registry(request.session.db)['ir.module.module']
            cr = module_obj.pool.cursor()
            auth_brute_module_id = module_obj.search(cr, SUPERUSER_ID, [('name', '=', 'auth_brute_force'), ('state', '=', 'installed')])
            cr.close()
            if len(auth_brute_module_id):
                environ = request.httprequest.environ
                remote = environ.get(
                    'HTTP_CF_CONNECTING_IP',
                    environ.get(
                        'HTTP_X_REAL_IP',
                        environ.get(
                            'HTTP_X_FORWARDED_FOR',
                            environ['REMOTE_ADDR'])))

                # Get registry and cursor
                config_obj = registry(request.session.db)['ir.config_parameter']
                attempt_obj = registry(
                    request.session.db)['res.authentication.attempt']
                banned_remote_obj = registry(
                    request.session.db)['res.banned.remote']
                cursor = attempt_obj.pool.cursor()

                # Get Settings
                max_attempts_qty = int(config_obj.search_read(
                    cursor, SUPERUSER_ID,
                    [('key', '=', 'auth_brute_force.max_attempt_qty')],
                    ['value'])[0]['value'])

                # Test if remote user is banned
                banned = banned_remote_obj.search(cursor, SUPERUSER_ID, [
                    ('remote', '=', remote)])
                if banned:
                    _logger.warning(
                        "Authentication tried from remote '%s'. The request has"
                        " been ignored because the remote has been banned after"
                        " %d attempts without success. Login tried : '%s'." % (
                            remote, max_attempts_qty, request.params['login']))
                    request.params['password'] = ''

                else:
                    # Try to authenticate
                    uid = request.session.authenticate(
                        request.session.db, request.params['login'],
                        request.params['password'])

                # Log attempt
                cursor.commit()
                attempt_obj.create(cursor, SUPERUSER_ID, {
                    'attempt_date': fields.Datetime.now(),
                    'login': request.params['login'],
                    'remote': remote,
                    'result': banned and 'banned' or (
                        uid and 'successfull' or 'failed'),
                })
                cursor.commit()
                if not banned and not uid:
                    # Get last bad attempts quantity
                    attempts_qty = len(attempt_obj.search_last_failed(
                        cursor, SUPERUSER_ID, remote))

                    if max_attempts_qty <= attempts_qty:
                        # We ban the remote
                        _logger.warning(
                            "Authentication failed from remote '%s'. "
                            "The remote has been banned. Login tried : '%s'." % (
                                remote, request.params['login']))
                        banned_remote_obj.create(cursor, SUPERUSER_ID, {
                            'remote': remote,
                            'ban_date': fields.Datetime.now(),
                        })
                        cursor.commit()

                    else:
                        _logger.warning(
                            "Authentication failed from remote '%s'."
                            " Login tried : '%s'. Attempt %d / %d." % (
                                remote, request.params['login'], attempts_qty,
                                max_attempts_qty))
                cursor.close()
            # auth_brute_force code ends
            else:
                uid = request.session.authenticate(request.session.db, request.params[
                                               'login'], request.params['password'])
            if uid is not False:
                return http.redirect_with_hash(redirect)
            request.uid = old_uid
            values['error'] = "Wrong login/password"
        return request.render('web.login', values)
