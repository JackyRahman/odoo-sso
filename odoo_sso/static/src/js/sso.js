odoo.define('odoo_sso.sso', function (require) {
    "use strict";
    var ajax = require('web.ajax');
    ajax.jsonRpc('/sso/me', 'call', {}).then(function (result) {
        console.log('SSO /me result:', result);
    });
});