{
    'name': 'Odoo SSO',
    'version': '16.0.1.0.0',
    'summary': 'Basic SSO login/logout with /me endpoint',
    'category': 'Tools',
    'author': 'Custom',
    'depends': ['web'],
    'data': ['views/templates.xml',
             'views/res_config_settings_view.xml'],
    'assets': {
        'web.assets_backend': [
            '/odoo_sso/static/src/js/sso.js',
        ],
    },
    'installable': True,
    'application': False,
}