+25
-0

from odoo import http
from odoo.http import request


class SSOController(http.Controller):
    @http.route('/sso/login', type='http', auth='public')
    def sso_login(self, **kwargs):
        """Redirect to configured SSO login URL."""
        icp = request.env['ir.config_parameter'].sudo()
        login_url = icp.get_param('odoo_sso.login_url', '/web')
        return request.redirect(login_url)

    @http.route('/sso/logout', type='http', auth='user')
    def sso_logout(self, **kwargs):
        """Logout and redirect to configured logout URL."""
        icp = request.env['ir.config_parameter'].sudo()
        logout_url = icp.get_param('odoo_sso.logout_url', '/web/login')
        request.session.logout()
        return request.redirect(logout_url)

    @http.route('/sso/me', type='json', auth='user')
    def sso_me(self):
        """Return basic information about the current user."""
        user = request.env.user
        return {'id': user.id, 'name': user.name, 'login': user.login}