function OAuthClient(oidc) {
    "use strict";
    this.url = oidc.conf.authorization_endpoint;
    this.oidc = oidc;
}

OAuthClient.prototype.createImplicitFlowRequest = function (clientid, callback, scope, responseType) {
    "use strict";

    responseType = responseType || "token";

    var state = (Date.now() + Math.random()) * Math.random();
    state = state.toString().replace(".", "");
    var nonce = (Date.now() + Math.random()) * Math.random();
    nonce = nonce.toString().replace(".", "");

    var url =
        this.url + "?" +
        "client_id=" + encodeURIComponent(clientid) + "&" +
        "redirect_uri=" + encodeURIComponent(callback) + "&" +
        "response_type=" + encodeURIComponent(responseType) + "&" +
        "scope=" + encodeURIComponent(scope) + "&" +
        "state=" + encodeURIComponent(state) + "&" +
        "nonce=" + encodeURIComponent(nonce);
        
    var ifr = {
        url: url,
        client_id: clientid,
        state: state,
        nonce: nonce,
        response_type: responseType,
        oidc: this.oidc
    };

    return ifr;
};

OAuthClient.prototype.parseResult = function (queryString) {
    "use strict";

    var params = {},
       regex = /([^&=]+)=([^&]*)/g,
        m;

    while (m = regex.exec(queryString)) { // jshint ignore:line
        params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
    }

    for (var prop in params) {
        return params;
    }
};


var OIDCDiscoveryFactory = function(authsrv_url){
    "use strict";
    
    var oidc = {};
    var url = authsrv_url + "/.well-known/openid-configuration";
                    
    //Get the OpenID Config Data
    return Promise.resolve($.get(url).then(function(data){
        oidc.conf = data;
        
        return oidc;
    }));
};



var JKWSCertificateFactory = function(oidc){
    "use strict";
    
    return Promise.resolve($.get(oidc.conf.jwks_uri).then(
        function(data){
            oidc.client_certificate = data.keys[0].x5c[0];
            return oidc;
        }
    ));    
};

var OAuthClientFactory = function(oidc){
    "use strict";
    
    var client = new OAuthClient(oidc);
    
    return client;
};
