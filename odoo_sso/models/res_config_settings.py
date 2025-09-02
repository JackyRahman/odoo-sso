from odoo import models, fields


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    sso_login_url = fields.Char(string='SSO Login URL',
                                config_parameter='odoo_sso.login_url')
    sso_logout_url = fields.Char(string='SSO Logout URL',
                                 config_parameter='odoo_sso.logout_url')