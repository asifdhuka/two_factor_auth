import openerp
from openerp import SUPERUSER_ID
from openerp import pooler, tools
from datetime import datetime, timedelta
from dateutil import parser
from openerp.osv import osv, fields
from openerp.tools.translate import _
import time
import struct
import hmac
import hashlib
import base64
import random
from Crypto.Cipher import DES


class res_users(osv.osv):
    _inherit = "res.users"

    def onchange_clear_secret_key(self, cr, uid, ids, two_factor_authentication, context=None):
        if two_factor_authentication:
            secret_key = self.generate_secret_key(cr, uid)
        else:
            secret_key = ''

        return {
            'value': {
                'secret_key': secret_key,
                'qr_code_template_id': False,
                'otp_template_id': False
            }
        }

    def generate_secret_key(self, cr, uid):
        # generate 16 charecter base32 encoded string
        secret_key = base64.b32encode(
            str(random.randint(1000000000, 9999999999)))
        key_exist = self.search(cr, uid, [('secret_key', '=', secret_key)])
        while len(key_exist):
            secret_key = base64.b32encode(
                str(random.randint(1000000000, 9999999999)))
            key_exist = self.search(cr, uid, [('secret_key', '=', secret_key)])
        return secret_key

    def get_secret_key_url(self, cr, uid, ids, context=None):

        user_record = self.browse(cr, uid, ids)
        username = user_record[0].login.replace(" ", "")
        secret_key = user_record[0].secret_key
        if not secret_key:
            raise osv.except_osv(_('Warning!'), _(
                "Please provide the secret key for the user."))
            return False
        domain = (user_record[0].company_id.name).replace(" ", "")

        url = "https://www.google.com/chart"
        url += "?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/"
        url += username + "@" + domain + "?secret=" + secret_key
        return url

    def send_secret_key(self, cr, uid, ids, context=None):

        template_id = self.pool.get('email.template').search(
            cr, uid, [('name', 'like', 'Send QR code')])
        user_obj = self.browse(cr, uid, ids[0])
        user_email = user_obj.email
        template_id = user_obj.qr_code_template_id.id

        if template_id:
            if not user_email:
                raise osv.except_osv(_('Warning!'), _(
                    "Please provide email id of the user."))
            else:

                return self.pool.get('email.template').send_mail(cr, uid, template_id, user_obj.id, True, context=context)

    def _check_secret_key(self, cr, uid, ids, context=None):
        record = self.browse(cr, uid, ids)
        for data in record:
            if data.two_factor_authentication:
                if not data.secret_key:
                    return False
                elif len(data.secret_key) < 16:
                    return False
                else:
                    for each in data.secret_key:
                        if each.isdigit():
                            # range(2,8) means from 2 to 8 ,excluding 8 and
                            # including 2
                            if not int(each) in range(2, 8):
                                return False
                        else:
                            if not each.isupper():
                                return False
        return True

    _columns = {
        'secret_key': fields.char('Google Authenticator Secret Key', size=16, help="Use combination of A-Z and 2-7 only to create a secret key."),
        'two_factor_authentication': fields.boolean("Two Factor Google Authenticator"),
        'otp': fields.char('OTP'),
        'otp_time': fields.datetime('OTP time'),
        'qr_code_template_id': fields.many2one('email.template', 'QR Code Template'),
        'otp_template_id': fields.many2one('email.template', 'Email OTP Template'),
    }

    _defaults = {
        'two_factor_authentication': False,
    }
    _constraints = [
        (_check_secret_key, 'Error: Enter secret key in correct format. Use combination of A-Z and 2-7 only to create a secret key.', ['secret_key'])]

    _sql_constraints = [
        ('secret_key_unique', 'UNIQUE (secret_key)', 'Secret key already exists !')
    ]

    @tools.ormcache(skiparg=2)
    def generate_secret_key_authentication(self, cr, secretkey, token):
        tm = int(time.time() / 30)

        secretkey = base64.b32decode(secretkey)

        # try 30 seconds behind and ahead as well
        for ix in [-1, 0, 1]:
            # convert timestamp to raw bytes
            b = struct.pack(">q", tm + ix)

        # generate HMAC-SHA1 from timestamp based on secret key
            hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB
            offset = ord(hm[-1]) & 0x0F
            truncatedHash = hm[offset:offset + 4]

        # get the code from it
            code = struct.unpack(">L", truncatedHash)[0]
            code &= 0x7FFFFFFF
            code %= 1000000

            if ("%06d" % code) == str(token):
                return True
        raise openerp.exceptions.AccessDenied()
        return False

    def authenticate_user(self, db, login, token):

        if not token:
            return False
        authenticated = False
        cr = pooler.get_db(db).cursor()
        try:
            # autocommit: our single update request will be performed atomically.
            # (In this way, there is no opportunity to have two transactions
            # interleaving their cr.execute()..cr.commit() calls and have one
            # of them rolled back due to a concurrent access.)
            cr.autocommit(True)
            # check if user exists
            res = self.search(cr, SUPERUSER_ID, [('login', '=', login)])
            if res:
                user_id = res[0]

                user_record = self.browse(cr, SUPERUSER_ID, user_id)
                secret_key = user_record.secret_key
                otp = user_record.otp
                # Check if OTP present in the database and compare with user entered OTP
                if otp and token == otp:
                    authenticated = True
                    user_record.write({'otp': False, 'otp_time': False})
                else:
                    # Generate secret key and compares with key entered by user
                    authenticated = self.generate_secret_key_authentication(
                        cr, secret_key, token)
        except openerp.exceptions.AccessDenied:
            authenticated = False
        finally:
            cr.close()
        return authenticated

    def authenticate_secret_key(self, db, login, token, user_agent_env):
        """ Template calls this function to verify entered secret key or OTP"""
        authenticated = self.authenticate_user(db, login, token)
        return authenticated

    def two_factor_enabled(self, db, login):
        """Verifies and returns whether user has enabled Two Factor Authentication"""
        if not login:
            return False
        # user_id = False
        cr = pooler.get_db(db).cursor()
        try:
            # autocommit: our single update request will be performed atomically.
            # (In this way, there is no opportunity to have two transactions
            # interleaving their cr.execute()..cr.commit() calls and have one
            # of them rolled back due to a concurrent access.)
            cr.autocommit(True)
            # check if user exists
            res = self.search(cr, SUPERUSER_ID, [('login', '=', login)])
            if res:
                user_id = res[0]

                user_record = self.browse(cr, SUPERUSER_ID, user_id)
                two_factor_enabled = user_record.two_factor_authentication
            else:
                two_factor_enabled = False

        except openerp.exceptions.AccessDenied:
            two_factor_enabled = False
        finally:
            cr.close()
        return two_factor_enabled

    def lost_mobile(self, db, login, context=None):
        """ Generates OTP and send it to user via OTP"""
        cr = pooler.get_db(db).cursor()
        res = self.search(cr, SUPERUSER_ID, [('login', '=', login)])
        cr.autocommit(True)
        if res:
            user_id = res[0]
            user_record = self.browse(cr, SUPERUSER_ID, user_id)
            secret_key = user_record.secret_key
            otp = self.generate_otp(secret_key)
            self.write(cr, SUPERUSER_ID, user_id, {'otp': otp, 'otp_time': datetime.now()})
            template_id = user_record.otp_template_id.id
            user_email = user_record.email
            if template_id:
                if not user_email:
                    raise osv.except_osv(_('Warning!'), _(
                        "Please provide email id of the user."))
                else:
                    return self.pool.get('email.template').send_mail(cr, SUPERUSER_ID, template_id, user_record.id, True, context=context)

    def generate_otp(self, secretkey):
        """ This method generates One time password for Lost mobile"""
        tm = int(time.time() / 30)
        secretkey = base64.b32decode(secretkey)
        b = struct.pack(">q", tm)
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset + 4]
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF
        code %= 1000000
        return code

    def purge_otp(self, cr, uid, context=None):
        """ Scheduler that deletes unused OTPs"""
        users = self.search(cr, SUPERUSER_ID, [('active', '=', True), ('otp', '!=', False)])
        for user in self.browse(cr, SUPERUSER_ID, users):
            otp_time = parser.parse(user.otp_time)
            if otp_time + timedelta(minutes=5) < datetime.utcnow():
                user.write({'otp': False, 'otp_time': False})
        return True

    def encyption(self, text):
        """Encryption of details passed via web request"""
        des = DES.new('!0LM@as1', DES.MODE_ECB)
        padding = len(text) % 8
        if padding:
            for i in range(8 - padding):
                text += 'a'
        cipher_text = base64.b64encode(des.encrypt(text))
        return cipher_text

    def decryption(self, text, length):
        """Decryption of details passed via web request"""
        des = DES.new('!0LM@as1', DES.MODE_ECB)
        cipher_text = des.decrypt(base64.b64decode(text))
        return cipher_text[:int(length)]


res_users()
