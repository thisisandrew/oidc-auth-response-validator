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
            rV.validate(request.good.oidc_conf.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [access_token] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__access_token__location_hash());
        
        try{
            rV.validate(request.good.oidc_conf.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [token_type] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__token_type__location_hash());
        
        try{
            rV.validate(request.good.oidc_conf.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingPropertyError");
        }
    });
    
    it("missing properties [state] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__state__location_hash());
        
        try{
            rV.validate(request.good.oidc_conf.client_certificate);
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
        rV = new OIDCAuthentication.ResponseValidator(request, response.location_hash());
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
        var status = rV.validate(request.good.oidc_conf.client_certificate);
        
        expect(status.signatureVerified).toBe(true);
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
        rV = new OIDCAuthentication.ResponseValidator(request, response.location_hash());
        token = rV.getPayload(id_token);
    });
    
    it("id_token matches the Issuer Identifier in the OIDC discovery against the 'iss' claim in the JWT", function(){
        expect(request.good.oidc_conf.issuer == rV.getClaim(token, 'iss')).toBe(true);
        
        token.iss = undefined;
        
        expect(function(){
            rV.getClaim(token, 'iss');
        }).toThrow();
        
        
        try {
            rV.getClaim(token, 'iss');
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingClaimError");
        }
    });
    
    it("id_token matches the Issuer Identifier in the OIDC discovery against the 'iss' claim in the JWT", function(){
        expect(request.good.oidc_conf.issuer == rV.getClaim(token, 'iss')).toBe(true);
        
        token.iss = undefined;
        
        expect(function(){
            rV.getClaim(token, 'iss');
        }).toThrow();
        
        
        try {
            rV.getClaim(token, 'iss');
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Error).toBe(true);
            expect(e.name).toBe("MissingClaimError");
        }
    });
    
    it("id_token has a valid 'aud' claim based on the client id in the request", function(){
        //TODO aud claim could be an array so this test should check if the claim is an array and the value is contained therein
        expect(request.good.client_id == rV.getClaim(token, 'aud')).toBe(true);
        expect(request.good.client_id == rV.getClaim(token, 'aud'))
    });

    //I have no token with multiple audiences so can't test the azp claim yet
    xit("id_token has 'azp' claim if 'aud' claim is array and contains client_id", function(){
        if (token.aud instanceof Array) {
            expect(rV.getClaim(token, 'azp')).toBeDefined();
            expect(request.good.client_id == rV.getClaim(token, 'azp'));
        }
    });
    
    it("id_token 'exp' claim must be after the current time", function(){
        var ts_now =  Math.floor(new Date().getTime()/ 1000); //UTC time
        
        expect(rV.getClaim(token, 'exp') > ts_now).toBe(true);
    });
});