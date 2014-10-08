function OAuthClient(url) {
    "use strict";
    this.url = url;
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

    return {
        url: url,
        state: state,
        nonce: nonce,
        response_type: responseType
    };
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
    return $.get(url).then(function(data){
        oidc.conf = data;
        
        return oidc;
    });
};



var JKWSCertificateFactory = function(oidc){
    "use strict";
    
    return $.get(oidc.conf.jwks_uri).then(
        function(data){
            oidc.client_certificate = data.keys[0].x5c[0];
            return oidc;
        }
    );    
};

var OAuthClientFactory = function(oidc){
    "use strict";
    
    var client = new OAuthClient(oidc.conf.authorization_endpoint);
    client.discoveredConfiguration = oidc.conf;
    client.certificate = oidc.client_certificate;
    
    return client;
};
