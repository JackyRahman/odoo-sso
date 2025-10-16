# -*- coding: utf-8 -*-
import base64
import binascii
import json
import os
import secrets
import time
import logging
import urllib.parse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from odoo import http, _
from odoo.http import request
from werkzeug.utils import redirect as werkzeug_redirect
from odoo.service import security
from odoo.addons.web.controllers.home import Home as WebHome

_logger = logging.getLogger(__name__)


class SSOMixin:
    def _get_param(self, key, default=""):
        return request.env["ir.config_parameter"].sudo().get_param(key, default) or default

    def _build_logout_redirect_uri(self):
        """
        Buat URL ke endpoint logout SSO, sertakan post_logout_redirect_uri
        yg menunjuk balik ke Odoo (default: /web/login).
        """
        base = self._get_param("auth_sso_bag.base_url", "https://dev-ssobag.air.id").rstrip("/")
        logout_ep = "/" + self._get_param("auth_sso_bag.logout_endpoint", "/svc-sso/oauth2/logout").lstrip("/")

        redirect_target = (self._get_param("auth_sso_bag.redirect_target") or "").strip()
        if not redirect_target:
            redirect_target = urllib.parse.urljoin(request.httprequest.host_url, "web/login")
        elif redirect_target.startswith("/"):
            redirect_target = urllib.parse.urljoin(request.httprequest.host_url, redirect_target.lstrip("/"))

        params = {"post_logout_redirect_uri": redirect_target}
        return f"{base}{logout_ep}?{urllib.parse.urlencode(params)}"
    
    def _build_redirect_uri(self):
        """Bangun redirect_uri absolut untuk callback Odoo."""

        configured = (self._get_param("auth_sso_bag.redirect_uri") or "").strip()
        if configured:
            if configured.startswith("/"):
                return urllib.parse.urljoin(request.httprequest.host_url, configured.lstrip("/"))
            return configured

        return urllib.parse.urljoin(request.httprequest.host_url, "auth/sso/callback")
    
    def _clear_all_cookies(self, response):
        to_clear = {"session_id", "tz", "fileToken", "frontend_lang", "oauth_state"}
        for name in set(to_clear) | set(request.httprequest.cookies.keys()):
            response.delete_cookie(name, path="/")
        return response


class SSOController(SSOMixin, http.Controller):

    @http.route("/auth/sso/login", type="http", auth="public", website=True, csrf=False)
    def sso_login(self, **kw):
        base = self._get_param("auth_sso_bag.base_url", "https://dev-ssobag.air.id").rstrip("/")
        auth_ep = self._get_param("auth_sso_bag.auth_endpoint", "/svc-sso/oauth2/auth")
        client_id = self._get_param("auth_sso_bag.client_id")
        scopes = self._get_param("auth_sso_bag.scopes", "openid profile personal empinfo email address phone")

        if not client_id:
            return request.render("web.login", {"error": _("SSO is not configured. Contact administrator.")})

        state = secrets.token_urlsafe(24)

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": self._build_redirect_uri(),
            "scope": scopes,
            "state": state,
        }
        url = f"{base}{auth_ep}?{urllib.parse.urlencode(params)}"
        _logger.info("[SSO] redirect to %s", url)

        resp = werkzeug_redirect(url)
        resp.set_cookie(
            "oauth_state",
            state,
            max_age=600,
            secure=(request.httprequest.scheme == "https"),
            httponly=True,
            samesite="Lax",
            path="/",
        )
        return resp

    @http.route("/auth/sso/callback", type="http", auth="public", website=True, csrf=False)
    def sso_callback(self, **kw):
        code = kw.get("code")
        state = kw.get("state")
        cookie_state = request.httprequest.cookies.get("oauth_state")
        _logger.info("[SSO] callback code(len)=%s state=%s cookie_state=%s",
                     len(code) if code else None, state, cookie_state)

        if not code:
            return werkzeug_redirect("/web/login?error=missing_code")

        if not cookie_state or cookie_state != state:
            return werkzeug_redirect("/web/login?error=invalid_state")

        base = self._get_param("auth_sso_bag.base_url", "https://dev-ssobag.air.id").rstrip("/")
        token_ep = self._get_param("auth_sso_bag.token_endpoint", "/svc-sso/oauth2/token")
        me_ep = self._get_param("auth_sso_bag.me_endpoint", "/svc-sso/oauth2/me")
        client_id = self._get_param("auth_sso_bag.client_id")
        client_secret = self._get_param("auth_sso_bag.client_secret")
        redirect_uri = self._build_redirect_uri()

        if not (client_id and client_secret):
            return werkzeug_redirect("/web/login?error=missing_client")

        token_url = f"{base}{token_ep}"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {auth_header}",
        }
        resp = requests.post(token_url, data=data, headers=headers, timeout=20)
        if resp.status_code // 100 != 2:
            _logger.error("[SSO] token exchange failed: %s %s", resp.status_code, resp.text)
            r = werkzeug_redirect("/web/login?error=exchange_failed")
            r.delete_cookie("oauth_state", path="/")
            return r

        tr = resp.json()
        access_token = tr.get("access_token")
        refresh_token = tr.get("refresh_token")
        expires_in = tr.get("expires_in", 3600)

        me_url = f"{base}{me_ep}"
        m = requests.get(me_url, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=20)
        if m.status_code // 100 != 2:
            _logger.error("[SSO] /me failed: %s %s", m.status_code, m.text)
            r = werkzeug_redirect("/web/login?error=me_failed")
            r.delete_cookie("oauth_state", path="/")
            return r

        profile = m.json() or {}
        _logger.error("[SSO] profile-----------: %s", profile,)
        password_hash = (
            profile.get("password_sso")
            or profile.get("password_hash")
            or profile.get("password_bcrypt")
            or profile.get("password")
        )
        password_hash = self._decrypt_password_hash(password_hash)
        sub = str(profile.get("sub") or profile.get("id") or "")
        email = profile.get("email") or ""
        name = profile.get("name") or profile.get("preferred_username") or email or sub or "SSO User"

        Users = request.env["res.users"].sudo()
        Link = request.env["auth.sso.account"].sudo()

        user = None
        if email:
            user = Users.search([("login", "=", email)], limit=1) or Users.search([("email", "=", email)], limit=1)
        if not user:
            user_vals = {
                "name": name,
                "login": email or f"user-{sub}@example.local",
                "email": email or False,
                "active": True,
            }
            if password_hash:
                user_vals["password_sso"] = password_hash
            user = Users.create(user_vals)
        elif password_hash:
            user.write({"password_sso": password_hash})

        link = Link.search([("provider", "=", "sso-bag"), ("subject", "=", sub)], limit=1)
        expiry = int(time.time()) + int(expires_in or 3600)
        if not link:
            Link.create({
                "provider": "sso-bag",
                "subject": sub or "",
                "user_id": user.id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expiry,
            })
        else:
            link.write({
                "user_id": user.id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expiry,
            })

        request.session.uid = user.id

        request.session.session_token = security.compute_session_token(request.session, request.env)
        request.session.rotate = True
        request.session.context = dict(request.session.context or {}, lang=user.lang or 'en_US')
        request.session.login = user.login

        request.env.cr.commit()
        _logger.info("[SSO] login success user_id=%s email=%s", user.id, user.email)

        next_url = kw.get("next") or "/web"
        final_resp = werkzeug_redirect(next_url)
        final_resp.delete_cookie("oauth_state", path="/")
        return final_resp
    def _decrypt_password_hash(self, encrypted_hash):
        """Decrypt password hash using configured RSA private key.

        The SSO returns the bcrypt hash encrypted with the public key. We need
        to use the private key stored in system parameters to obtain the
        original bcrypt hash before storing it. If the private key is missing
        or decryption fails, the value is returned unchanged to avoid breaking
        login for older payloads.
        """

        if not encrypted_hash:
            return encrypted_hash

        private_key_pem = (self._get_param("auth_sso_bag.private_key") or "").strip()
        if not private_key_pem:
            return encrypted_hash

        private_key = None
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        except (ValueError, TypeError):
            try:
                key_bytes = base64.b64decode(private_key_pem)
                private_key = serialization.load_der_private_key(key_bytes, password=None)
            except Exception as exc:
                _logger.error("[SSO] invalid RSA private key: %s", exc)
                return encrypted_hash

        try:
            encrypted_bytes = base64.b64decode(encrypted_hash, validate=True)
        except (binascii.Error, ValueError) as exc:
            _logger.warning("[SSO] password_sso is not valid base64: %s", exc)
            return encrypted_hash

        try:
            decrypted_bytes = private_key.decrypt(
                encrypted_bytes,
                padding.PKCS1v15(),
            )
        except Exception as exc:
            _logger.error("[SSO] failed to decrypt password_sso: %s", exc)
            return encrypted_hash

        try:
            return decrypted_bytes.decode()
        except UnicodeDecodeError:
            return decrypted_bytes.decode("utf-8", errors="ignore")


class SSOWebHome(WebHome, SSOMixin):
    """Override logout supaya selalu lewat SSO."""

    @http.route("/web/logout", type="http", auth="public", csrf=False)
    def web_logout(self, redirect_url="/web"):
        request.session.logout(keep_db=True)

        request.session.session_token = security.compute_session_token(request.session, request.env)
        request.session.rotate = True

        resp = werkzeug_redirect(self._build_logout_redirect_uri())
        return self._clear_all_cookies(resp)

    @http.route("/web/session/logout", type="http", auth="user", csrf=False)
    def web_session_logout_http(self):
        """Allow logging out via regular HTTP GET requests."""
        request.session.logout(keep_db=True)
        resp = werkzeug_redirect(self._build_logout_redirect_uri())
        return self._clear_all_cookies(resp)

    # @http.route("/web/session/logout", type="json", auth="user")
    # def web_session_logout(self):
    #     """
    #     Dipanggil oleh webclient via JSON-RPC.
    #     Kita kembalikan JSON {logout: True, redirect_url: <SSO logout>}.
    #     Webclient akan melakukan redirect ke URL tsb.
    #     """
    #     request.session.logout(keep_db=True)
    #     payload = {
    #         "logout": True,
    #         "redirect_url": self._build_logout_redirect_uri(),
    #     }
    #     resp = request.make_json_response(payload)
    #     return self._clear_all_cookies(resp)