# -*- coding: utf-8 -*-
from odoo import api, fields, models

class AuthSSOAccount(models.Model):
    _name = "auth.sso.account"
    _description = "External SSO Account Link"
    _rec_name = "subject"

    provider = fields.Char(required=True, default="sso-bag", index=True)
    subject = fields.Char(required=True, index=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")

    access_token = fields.Char()
    refresh_token = fields.Char()
    expires_at = fields.Integer(string="Access Expiry (epoch)")

    _sql_constraints = [
        ("provider_subject_uniq", "unique(provider,subject)", "SSO subject already linked.")
    ]
