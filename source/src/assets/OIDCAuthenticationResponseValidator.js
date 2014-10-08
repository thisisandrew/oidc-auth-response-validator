/**
 * OIDCAuthenticationResponseValidator
 *     for Client-side Apps with unencrypted JSON Web Tokens
 *
 * @author androohill@gmail.com
 * Offers client side validation of the OIDC Authentication Response from an Authorization Server
 *
 * Supported Response Type Validations
 * ☒ Authorization Code Flow (Response Type 'code') see http://openid.net/specs/openid-connect-core-1_0.html#AuthResponseValidation
 * ☑ Implicit Flow (Response Type 'id_token token' OR 'id_token') see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponseValidation
 * ☒ Hybrid Flow (Response Type contains 'code' AND ('id_token' OR 'token' OR both)) see http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponseValidation
 *
 * So right now this is only good for client side apps but may be enhanced
 * for server side js apps to handle Authorization Code Flow and Hybrid FLow
 *
 * @depends
 * jquery ^1.10.0
 * jsjws
 * jsrsasign
 *
 * @uses
 * promise ~6.0.0
 */

var OIDCAuthentication = OIDCAuthentication || {}; 

/**
 * @param request must contain a response_type e.g. { response_type: 'code'}
 * @param response must be a URI query string/fragment  e.g. scope=email&state=4321&id_token=y34yt4uy324t23 etc - leading # can be included if fragment
 */
OIDCAuthentication.ResponseValidator = function(request, response){
    this.request = request;
    this.response = null;
    this.errors = [];
    this.id_token = null;
    this.access_token = null;
    
    /**
     * Check for a request
     */
    if(typeof request === "undefined" || request == null) {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingParameterError("request");
    }
    
    /**
     * Check for response
     */
    if(typeof response === "undefined" || response == null) {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingParameterError("reponse");
    }
    
    /**
     * Check the response for usability
     */
    var parseResponse = function(response){
        if (response.indexOf('#') == 0) {
            response = response.substring(1);
        }
        
        var params = {},
            regex = /([^&=]+)=([^&]*)/g,
            m;
     
        while (m = regex.exec(response)) { // jshint ignore:line
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }
     
        for (var prop in params) {
            return params;
        }
        
        return params;
    };
    this.response = parseResponse(response);
    if(this.response == {}) {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingParameterError("response");
    }
    
    
    /**
     * Determine which flow we are using.
     * http://openid.net/specs/openid-connect-core-1_0.html#Authentication
     * OpenID Connect "response_type" Values 
     */
    if(this.request.response_type == "code") {
        this.flow = new OIDCAuthentication.Flows.AuthorizationCode(this);
    } else if(this.request.response_type == "id_token token" || this.request.response_type == "id_token") {
        this.flow = new OIDCAuthentication.Flows.Implicit(this);
    } else if(this.request.response_type.indexOf("code") > -1
              && (this.request.response_type.indexOf("id_token") > -1 || this.request.response_type.indexOf("token") > -1)) {
        this.flow = new OIDCAuthentication.Flows.Hybrid(this);
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.UnsupportedFlowError();
    }

    /**
     * @param cert is the public key from the OIDC jwks_uri endpoint at keys[0].x5c[0] -
     * You can get the jwks_uri from your AUthorization Servers .well-known/openid-configuration endpoint - http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
     */
    this.validate = function(cert){
        return this.flow.validate(this.response, cert).then(function(valid){
            debugger;
            return valid;
        }).catch(function(e){
            debugger;
            throw e;
        });
    };
};


//Using Promises? Use the Factory to return one.
OIDCAuthentication.ResponseValidatorFactory = function(request, response){
    return new Promise(function(fulfill, reject){
        var rV = new OIDCAuthentication.ResponseValidator(request, response);
        fulfill(rV);
    });
};


OIDCAuthentication.Flows = {
    //Not yet supported
    AuthorizationCode: function(){
        this.validate = function(response){
            throw new OIDCAuthentication.ResponseValidator.Errors.NotYetImplemented() 
        };
    },
    
    //Supported
    Implicit: function(responseValidator){
        this.rV = responseValidator;
        
        this.validate = function (response, cert) {
            if(this.rV.verifyState() && this.rV.hasProperty('id_token')){
                try {
                    var payload = this.rV.verifyTokenSignatureAndGetPayload(this.rV.response.id_token, cert);
                    return payload;
                 } catch(e) {
                    throw e;
                 }
            }
            
            return false;
        };
    },
    
    //Supported
    Hybrid: function(){
        this.validate = function(){
            throw new OIDCAuthentication.ResponseValidator.Errors.NotYetImplemented();
        };
    }
};

OIDCAuthentication.ResponseValidator.prototype.hasProperty = function(propertyName){
    return this.response.hasOwnProperty(propertyName);
};

OIDCAuthentication.ResponseValidator.prototype.tokenHasClaim = function(claimName){
    
    //return this.response.hasOwnProperty(propertyName);
};

OIDCAuthentication.ResponseValidator.prototype.verifyState = function(){
    if (this.hasProperty('state')) {
        if (this.request.state === this.response.state) {
            return true;
        }
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingProperty("state");
    }
};

OIDCAuthentication.ResponseValidator.prototype.verifyNonce = function(){
    if (this.hasProperty('nonce')) {
        if (this.request.nonce === this.response.nonce) {
            return true;
        }
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingProperty("nonce");
    }
};


//The cert is the public key from the OIDC jwks_uri endpoint at keys[0].x5c[0];
OIDCAuthentication.ResponseValidator.prototype.verifyTokenSignatureAndGetPayload = function(token, cert){
    var verfd = false;
    var tokenPayload = {};
    
    try {
        var hCert = X509.pemToHex(cert);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        var rsa = new RSAKey();
        rsa.setPublic(a[0], a[1]);
        
        result = KJUR.jws.JWS.verify(token, rsa);
        if (result) {
            //Signature is valid
            verfd = true;
            var jws = new KJUR.jws.JWS();
            
            patchJWS(jws); //Overrides the method 'parseJWS' on the instance of KJUR.jws.JWS
            
            jws.parseJWS(token, false);
        
            var tokenPayload = JSON.parse(jws.parsedJWS.payloadS);
            return { verified: verfd, payload: tokenPayload};
        } else {
             return { verified: verfd, payload: {} };
        }
    } catch(e) {
         throw new OIDCAuthentication.ResponseValidator.Errors.TokenSignatureValidationError(e);
    }
};


/**
 * Error Types
 */
OIDCAuthentication.ResponseValidator.Errors = {
    MissingParameterError: function(param){
        this.stack = new Error().stack;
        this.name = "MissingParameterError";
        this.message = "missing parameter: " + param;
        this.parameter = param;
    },
    
    MissingPropertyError: function(prop){
        this.stack = new Error().stack;
        this.name = "MissingPropertyError";
        this.message = "missing property: " + prop;
        this.property = prop;
    },
    
    InvalidResponseTypeError: function(){
        this.stack = new Error().stack;
        this.name = "InvalidResponseTypeError";
        this.message = "invalid reponse_type";
    },
    
    InvalidTokenSignatureError: function(){
        this.stack = new Error().stack;
        this.name = "InvalidTokenSignatureError";
        this.message = "invalid token signature";
    },
    
    TokenSignatureValidationError: function(e){
        this.name = "TokenSignatureValidationError";
        this.message = "token signature validation error in jws lib";
        this.stack = e.stack;
    },
    
        
    NotYetImplemented: function(){
        this.stack = new Error().stack;
        this.message = "not yet implemented";
    }
}

