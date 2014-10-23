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
        return this.flow.validate(cert);
    };
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
        
        //returns true if valid or throws a meaningingful usable exception
        this.validate = function (cert) {
            //Implicit flow requires a number of steps to check the id_token
            //http://tools.ietf.org/html/rfc6749#section-4.2.2
            
            //Check the response contains the basics
            if(!this.rV.hasProperty('state')) {
                throw new OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError("state");
            }
            
            if(!this.rV.hasProperty('token_type')) {
                throw new OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError("token_type");
            }
               
            if(!this.rV.hasProperty('id_token')) {
                throw new OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError("id_token");
            }
               
            if(!this.rV.hasProperty('access_token')) {
                throw new OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError("access_token");
            }
            
            if(!this.rV.verifyState(this.rV.request.state, this.rV.response.state)) {
                throw new OIDCAuthentication.ResponseValidator.Errors.InvalidPropertyError("state");
            }
            
            //Get the payload of the id_token
            var id_token_payload = this.rV.getPayload(this.rV.response.id_token);
            
            if(!this.rV.verifyClaim(id_token_payload, 'iss', this.rV.request.oidc.conf.issuer)) {
                throw new OIDCAuthentication.ResponseValidator.Errors.InvalidClaimError("iss");
            }
            
            if(!this.rV.verifyAudience(id_token_payload, this.rV.request.client_id)){
                throw new OIDCAuthentication.ResponseValidator.Errors.InvalidClaimError("aud");
            }
            
            if(!this.rV.isTokenNotExpired(id_token_payload)) {
                throw new OIDCAuthentication.ResponseValidator.Errors.TokenExpiredError();
            }
            
            //Let's have a stab at that JWS signature then
            try {
                if(!this.rV.verifyTokenSignature(this.rV.response.id_token, cert)) {
                    throw new OIDCAuthentication.ResponseValidator.Errors.TokenSignatureValidationError();
                }
            } catch(e) {
                throw new OIDCAuthentication.ResponseValidator.Errors.TokenSignatureValidationError(e);
            }
            
            if(!this.rV.verifyNonce(this.rV.request.nonce, id_token_payload)){
                throw new OIDCAuthentication.ResponseValidator.Errors.InvalidClaimError("nonce");
            }
          
            //Check the at_hash claim on the id_token if an access token is present in the response
            if (typeof this.rV.response.access_token != 'undefined') {
                if (!this.rV.verifyAccessTokenHash(this.rV.response.id_token, this.rV.response.access_token)) {
                    throw new OIDCAuthentication.ResponseValidator.Errors.InvalidClaimError("at_hash");
                }    
            }
            
            return true;
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
    if(this.response.hasOwnProperty(propertyName) && typeof this.response[propertyName] !== 'undefined'){
        return true;    
    } else {
        return false;
    }
};

OIDCAuthentication.ResponseValidator.prototype.verifyClaim = function(tokenPayload, claimName, claimValue){
    //The claim could be array of values
    if(this.getClaim(tokenPayload, claimName) instanceof Array){
        for(i = 0; i < tokenPayload.length; i++) {
            if(tokenPayload[i] === claimValue) {
                return true;
            }
        }
    } else {
        if(tokenPayload[claimName] === claimValue){
            return true;
        }
    }
    
    return false;
};

OIDCAuthentication.ResponseValidator.prototype.hasClaim = function(tokenPayload, claimName){
    if (tokenPayload.hasOwnProperty(claimName) && typeof tokenPayload[claimName] !== 'undefined') {
        return true;
    } else {
        return false;
        //throw new OIDCAuthentication.ResponseValidator.Errors.MissingClaimError(claimName);
    }
};

OIDCAuthentication.ResponseValidator.prototype.getClaim = function(tokenPayload, claimName){
    if (this.hasClaim(tokenPayload, claimName)) {
        return tokenPayload[claimName];
    } else {
        return false;
        //throw new OIDCAuthentication.ResponseValidator.Errors.MissingClaimError(claimName);
    }
};

OIDCAuthentication.ResponseValidator.prototype.verifyAudience = function(tokenPayload, claimValue){
    //The aud claim must contain the client_id (could be in an array)
    if (this.verifyClaim(tokenPayload, "aud", claimValue)) {
        if(this.getClaim(tokenPayload, "aud") instanceof Array){
            return this.verifyClaim(tokenPayload, 'azp', claimValue);
        }
        
        return true;
    }
    
    return false;
};

OIDCAuthentication.ResponseValidator.prototype.isTokenNotExpired = function(tokenPayload){
    var ts_now =  Math.floor(new Date().getTime()/ 1000); //UTC time
    
    if(this.getClaim(tokenPayload, "exp") > ts_now) {
        return true;
    } else {
        return false;
    }
}

OIDCAuthentication.ResponseValidator.prototype.verifyState = function(request_state, response_state){
    if (request_state === response_state) {
        return true;
    } else {
        return false;
    }
};

OIDCAuthentication.ResponseValidator.prototype.verifyNonce = function(request_nonce, tokenPayload){
    if (typeof request_nonce !== 'undefined'){
        if (this.getClaim(tokenPayload, 'nonce') == request_nonce) {
            return true;
        }
    } else {
        //No nonce in request so its not necessary to verify
        return true;
    }
    
    return false;
};


//The cert is the public key from the OIDC jwks_uri endpoint at keys[0].x5c[0];
//Token is passed in as it could be *any* token id_token, access_token, unicorn_token...
OIDCAuthentication.ResponseValidator.prototype.verifyTokenSignature = function(token, cert){
    //Convert raw base64 encoded PEM to RSAKey
    var hCert = X509.pemToHex(cert);
    var a = X509.getPublicKeyHexArrayFromCertHex(hCert);
    var rsa = new RSAKey();
    rsa.setPublic(a[0], a[1]);
    
    var result = KJUR.jws.JWS.verify(token, rsa);
    if (result) {
        return true;
    } 
    
    return false;
};

OIDCAuthentication.ResponseValidator.prototype.verifyAccessTokenHash = function(id_token, access_token){
    
    //Depends on the alg
    var idTokenHeader = this.getHeader(this.response.id_token);
    var sigAlg = this.getClaim(idTokenHeader, 'alg');
    
    if (sigAlg != "RS256" && sigAlg != "RS512" &&
        sigAlg != "PS256" && sigAlg != "PS512")
        throw "JWS signature algorithm not supported: " + sigAlg;
   
    if (sigAlg.substr(2) == "256") hashAlg = "sha256";
    if (sigAlg.substr(2) == "512") hashAlg = "sha512";
    
    //Hash the access token with the alg    
    var hash = KJUR.crypto.Util.hashString(access_token, hashAlg);
    
    //Base64URL encode leftmost half
    var at_hash = b64tob64u(hex2b64(hash.substring(0, Math.floor(hash.length / 2))));
    
    var idTokenPayload = this.getPayload(id_token);
    
    if (this.getClaim(idTokenPayload, "at_hash") == at_hash) {
        return true;
    }
    
    return false;
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
        throw new OIDCAuthentication.ResponseValidator.Errors.TokenPayloadInvalidError(e);
    }
    
    return tokenPayload;
};

//Get the parsed token so we can inspect/check the payload
//Token is passed in as it could be *any* token id_token, access_token, unicorn_token...
OIDCAuthentication.ResponseValidator.prototype.getHeader = function(token){
    var tokenHeader = {};
    var jws = new KJUR.jws.JWS();
            
    patchJWS(jws); //Overrides the method 'parseJWS' on the instance of KJUR.jws.JWS
    
    jws.parseJWS(token, false);

    try {
        tokenHeader = JSON.parse(jws.parsedJWS.headS);
    } catch(e) {
        throw new OIDCAuthentication.ResponseValidator.Errors.TokenHeaderInvalidError(e);
    }
    
    return tokenHeader;
};

/**
 * Error Types
 */
OIDCAuthentication.ResponseValidator.Error = function (name, message) {
  this.name = name;
  this.message = message || 'Default Message';
};
OIDCAuthentication.ResponseValidator.Error.prototype = new Error();
OIDCAuthentication.ResponseValidator.Error.prototype.constructor = OIDCAuthentication.ResponseValidator.Error;


OIDCAuthentication.ResponseValidator.Errors = {
    MissingParameterError: function MissingParameterError(param){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "missing parameter: " + param);
    },
    
    MissingPropertyError: function MissingPropertyError(prop){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "missing property: " + prop);
    },
    
    InvalidPropertyError: function InvalidPropertyError(prop){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "invalid property: " + prop);
    },
    
    InvalidResponseTypeError: function InvalidResponseTypeError(){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "invalid reponse_type");
    },
    
    TokenSignatureValidationError: function TokenSignatureValidationError(e){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "token signature validation error in jws lib");
    },
    
    TokenPayloadInvalidError: function TokenPayloadInvalidError(e){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "token payload is invalid");
    },
    
    TokenHeaderInvalidError: function TokenHeaderInvalidError(e){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "token header is invalid");
    },
    
    MissingClaimError: function MissingClaimError(claim){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "missing claim: " + claim);
    },
    
    InvalidClaimError: function InvalidClaimError(claim){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "invalid claim: " + claim);
    },
    
    TokenExpiredError: function TokenExpiredError(){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "expired token");
    },
        
    NotYetImplemented: function NotYetImplemented(){
        return new OIDCAuthentication.ResponseValidator.Error(this.constructor.name, "not yet implemented");
    }
}

