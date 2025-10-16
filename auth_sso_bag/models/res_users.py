# -*- coding: utf-8 -*-
import logging

from odoo import _, fields, models
from odoo.exceptions import AccessDenied
from passlib.hash import bcrypt


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    password_sso = fields.Char(string="SSO Password", copy=False)

    def _check_password_sso(self, password):
        """Check the given password against the stored SSO bcrypt hash."""
        self.ensure_one()

        if not self.password_sso:
            return False

        hashed = self.password_sso
        if isinstance(hashed, bytes):
            hashed = hashed.decode()

        password_to_check = password.decode() if isinstance(password, bytes) else password

        try:
            return bcrypt.verify(password_to_check, hashed)
        except (ValueError, TypeError):
            _logger.exception("Invalid bcrypt hash stored for user %s", self.id)
            return False

    def _check_credentials(self, password, env):
        self.ensure_one()

        if self.password_sso:
            if self._check_password_sso(password):
                return True
            _logger.info("SSO password check failed for user %s", self.id)
            raise AccessDenied(_("Invalid login credentials"))

        return super()._check_credentials(password, env)