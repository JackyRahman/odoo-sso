# -*- coding: utf-8 -*-
from odoo import api, fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    auth_sso_bag_base_url = fields.Char(string="SSO Base URL", config_parameter="auth_sso_bag.base_url", default="https://dev-ssobag.air.id")
    auth_sso_bag_auth_endpoint = fields.Char(string="Authorize Endpoint", config_parameter="auth_sso_bag.auth_endpoint", default="/svc-sso/oauth2/auth")
    auth_sso_bag_token_endpoint = fields.Char(string="Token Endpoint", config_parameter="auth_sso_bag.token_endpoint", default="/svc-sso/oauth2/token")
    auth_sso_bag_me_endpoint = fields.Char(string="UserInfo (/me) Endpoint", config_parameter="auth_sso_bag.me_endpoint", default="/svc-sso/oauth2/me")
    auth_sso_bag_logout_endpoint = fields.Char(string="Logout Endpoint", config_parameter="auth_sso_bag.logout_endpoint", default="/svc-sso/oauth2/logout")
    auth_sso_bag_redirect_target = fields.Char(
        string="Logout Redirect Target",
        config_parameter="auth_sso_bag.redirect_target",
        default="/web/login",
        help="Absolute URL or path used as post_logout_redirect_uri after logging out from IAM.",
    )
    auth_sso_bag_client_id = fields.Char(string="Client ID", config_parameter="auth_sso_bag.client_id", default="client_id")
    auth_sso_bag_client_secret = fields.Char(string="Client Secret", config_parameter="auth_sso_bag.client_secret", default="client_secret")
    auth_sso_bag_scopes = fields.Char(string="Scopes", config_parameter="auth_sso_bag.scopes", default="openid profile personal empinfo email address phone")
    auth_sso_bag_private_key = fields.Char(
        string="RSA Private Key",
        config_parameter="auth_sso_bag.private_key",
        help="PEM encoded RSA private key used to decrypt SSO password hashes.",
        size=4096,
    )

    show_sso_login_button = fields.Boolean(string="Show SSO Button on Login", config_parameter="auth_sso_bag.show_button", default=True)

    @api.model
    def get_values(self):
        res = super().get_values()
        # nothing special, let config_parameter handle persist
        return res
