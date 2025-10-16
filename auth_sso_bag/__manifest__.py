# -*- coding: utf-8 -*-
{
    "name": "SSO (OAuth2) for Odoo - BAG",
    "summary": "Login Odoo via SSO BAG (Authorization Code + /oauth2/me)",
    "version": "16.0.1.0.0",
    "license": "LGPL-3",
    "author": "Your Team",
    "category": "Authentication",
    "website": "https://unotek.co.id",
    "depends": ["base", "web"],
    "data": [
        "security/ir.model.access.csv",
        "data/ir_config_parameter_data.xml",
        "views/res_config_settings_views.xml",
        "views/templates.xml",
    ],
    "external_dependencies": {"python": ["cryptography"]},
    "installable": True,
    "application": False,
}
