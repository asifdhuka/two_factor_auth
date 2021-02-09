openerp.two_factor_auth = function(instance) {
	instance.two_factor_auth.tauth_login = instance.web.Widget.extend({
		template:'tauth_login',
});
};
openerp.web.client_actions.add("tauth_login", "instance.two_factor_auth.tauth_login");