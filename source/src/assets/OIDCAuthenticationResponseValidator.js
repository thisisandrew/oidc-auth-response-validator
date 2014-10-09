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
 *
 * @depends
 * jquery ^1.10.0
 * jsjws 3.0.0
 * jsrsasign 1.7.0
 *
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
        throw new OIDCAuthentication.ResponseValidator.Errors.InvalidResponseTypeError();
    }

    /**
     * @param cert is the public key from the OIDC jwks_uri endpoint at keys[0].x5c[0] -
     * You can get the jwks_uri from your AUthorization Servers .well-known/openid-configuration endpoint - http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
     */
    this.validate = function(cert){
        //gets and return a status object
        return this.flow.validate(this.response, cert);
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
        var status = {};
        this.rV = responseValidator;
        
        this.validate = function (response, cert) {
            if(this.rV.hasProperty('state') && this.rV.hasProperty('token_type') && this.rV.hasProperty('id_token') && this.rV.hasProperty('access_token') && this.rV.verifyState()){
                try {
                    //Implicit flow requires a number of steps to check the id_token
                    //http://tools.ietf.org/html/rfc6749#section-4.2.2
                    
                    if(this.rV.verifyTokenSignature(this.rV.response.id_token, cert)) {
                        status.signatureVerified = true;
                        
                        var id_token_payload = this.rV.getPayload(this.rV.response.id_token);
                        
                        
                    } else {
                        status.signatureVerified = false;
                    }
                    return status;
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
    if(this.response.hasOwnProperty(propertyName)){
        return true;    
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError(propertyName);
    }
};

OIDCAuthentication.ResponseValidator.prototype.tokenHasClaim = function(tokenPayload, claimName){
    
    //return this.response.hasOwnProperty(propertyName);
};

OIDCAuthentication.ResponseValidator.prototype.verifyState = function(){
    if (this.request.state === this.response.state) {
        return true;
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.InvalidProperty("state");
    }
};

OIDCAuthentication.ResponseValidator.prototype.verifyNonce = function(){
    if (this.request.nonce === this.response.nonce) {
        return true;
    } else {
        throw new OIDCAuthentication.ResponseValidator.Errors.InvalidProperty("nonce");
    }
};


//The cert is the public key from the OIDC jwks_uri endpoint at keys[0].x5c[0];
//Token is passed in as it could be *any* token id_token, access_token, unicorn_token...
OIDCAuthentication.ResponseValidator.prototype.verifyTokenSignature = function(token, cert){
    try {
        //Convert raw base64 encoded PEM to RSAKey
        var hCert = X509.pemToHex(cert);
        var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
        var rsa = new RSAKey();
        rsa.setPublic(a[0], a[1]);
        
        result = KJUR.jws.JWS.verify(token, rsa);
        if (result) {
            //Signature is valid
            return true;
        } else {
             return false;
        }
    } catch(e) {
         throw new OIDCAuthentication.ResponseValidator.Errors.TokenSignatureValidationError(e);
    }
};

//Get the parsed token so we can inspect/check the payload
//Token is passed in as it could be *any* token id_token, access_token, unicorn_token...
OIDCAuthentication.ResponseValidator.prototype.getPayload = function(token){
    var tokenPayload = {};
    var jws = new KJUR.jws.JWS();
            
    patchJWS(jws); //Overrides the method 'parseJWS' on the instance of KJUR.jws.JWS
    
    jws.parseJWS(token, false);

    try {
        tokenPayload = JSON.parse(jws.parsedJWS.payloadS);
    } catch(e) {
        throw new TokenPayloadInvalidError(e);
    }
    
    return tokenPayload;
}

//Verify the salient parts of the payload
OIDCAuthentication.ResponseValidator.prototype.verifyPayload = function(payload){
    
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
    
    InvalidPropertyError: function(prop){
        this.stack = new Error().stack;
        this.name = "InvalidPropertyError";
        this.message = "invalid property: " + prop;
        this.property = prop;
    },
    
    InvalidResponseTypeError: function(){
        this.stack = new Error().stack;
        this.name = "InvalidResponseTypeError";
        this.message = "invalid reponse_type";
    },
    
    /*
    InvalidTokenSignatureError: function(){
        this.stack = new Error().stack;
        this.name = "InvalidTokenSignatureError";
        this.message = "invalid token signature";
    },
    */
    
    TokenSignatureValidationError: function(e){
        this.name = "TokenSignatureValidationError";
        this.message = "token signature validation error in jws lib";
        this.stack = e.stack;
    },
    
    TokenPayloadInvalidError: function(e){
        this.name = "TokenPayloadInvalidError";
        this.message = "token payload is invalid";
        this.stack = e.stack;
    },
    
        
    NotYetImplemented: function(){
        this.stack = new Error().stack;
        this.message = "not yet implemented";
    }
}

