describe('OIDC Validator cannot', function () {
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    
    it("be created with null request", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(null, response.location_hash());
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(null, response.location_hash());
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingParameterError");
        }
    });
    
    it("be created with undefined request", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(undefined, response.location_hash());
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(undefined, response.location_hash());
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingParameterError");
        }
    });
    
    it("be created with null response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request.good, null);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request, null);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingParameterError");
        }
    });
    
    it("be created with undefined response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request.good, undefined);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request.good, undefined);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingParameterError");
        }
    });
});

describe('OIDC Validator rejects', function(){
    var response = FIXTURE.response;
    var request = FIXTURE.request;
    //var oidc = FIXTURE.oidc;
    
    it("bad response type  in request", function(){
        try{
            new OIDCAuthentication.ResponseValidator(request.bad, response.location_hash());
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("InvalidResponseTypeError");
        }
    });
    
    it("missing properties [id_token] in response", function(){
        var rV =  new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__id_token__location_hash());
        
        try{
            rV.validate(request.good.oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [access_token] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__access_token__location_hash());
        
        try{
            rV.validate(request.good.oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [token_type] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__token_type__location_hash());
        
        try{
            rV.validate(request.good.oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [state] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__state__location_hash());
        
        try{
            rV.validate(request.good.oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
});

describe('OIDC Validator', function(){
    var id_token = FIXTURE.id_token;
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    //var oidc = FIXTURE.oidc;
    
    var rV;
    
    beforeEach(function(){
        rV = new OIDCAuthentication.ResponseValidator(request.good, response.location_hash());
    });
    

    it("can be created with a valid parameters", function(){
        expect(rV instanceof OIDCAuthentication.ResponseValidator).toBe(true);
    });
    
    it("has a valid response_type and assigns correct flow from request.response_type ('id_token token' - > Implicit Flow)", function(){
        expect(rV.flow instanceof OIDCAuthentication.Flows.Implicit).toBe(true);
    });
    
    it("validates the state parameter", function(){
        expect(rV.verifyState()).toBe(true);
    });
    
    it("validates the JWS Signature from the certificate (PEM)", function(){
        var status = rV.verifyTokenSignature(id_token, request.good.oidc.client_certificate);
        
        expect(status).toBe(true);
    });
    
    it("gets a payload from a token", function(){
        var token = rV.getPayload(id_token);
        
        expect(typeof token).toBe("object");
    });
});

describe('OIDC Validator Token', function(){
    var id_token = FIXTURE.id_token;
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    
    var rV, token;
    
    beforeEach(function(){
        rV = new OIDCAuthentication.ResponseValidator(request.good, response.location_hash());
        tokenPayload = rV.getPayload(id_token);
    });
    
    it("id_token matches the Issuer Identifier in the OIDC discovery against the 'iss' claim in the JWT", function(){
        expect(rV.verifyClaim(tokenPayload, "iss", request.good.oidc.conf.issuer)).toBe(true);
       
        tokenPayload.iss = undefined;
        
        expect(rV.verifyClaim(tokenPayload, "iss", request.good.oidc.conf.issuer)).toBe(false);
    });
    
    it("id_token has a valid 'aud' claim based on the client id in the request", function(){
        //TODO aud claim could be an array so this test should check if the claim is an array and the value is contained therein
        expect(rV.verifyAudience(tokenPayload, request.good.client_id)).toBe(true);
        
    });

    it("id_token 'exp' claim must be after the current time", function(){
        //Out token has expired so this should be false
        expect(rV.isTokenExpired(tokenPayload)).toBe(false);
    });
    
    it("validates the 'nonce' claim", function(){
        expect(rV.verifyNonce()).toBe(true);
    });
});

describe('OIDC Validator validates', function(){
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    
    var rV;
    
    beforeEach(function(){
        rV = new OIDCAuthentication.ResponseValidator(request.good, response.location_hash());
    });
    
    it("a good request and response", function(){
        expect(rV.validate(request.good.oidc.conf.client_certificate)).toThrow();
    });
});