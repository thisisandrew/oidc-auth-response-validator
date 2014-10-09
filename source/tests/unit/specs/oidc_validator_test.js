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
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("be created with undefined request", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(undefined, response.location_hash());
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(undefined, response.location_hash());
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("be created with null response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request.good, null);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request, null);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("be created with undefined response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request.good, undefined);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request.good, undefined);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
});

describe('OIDC Validator rejects', function(){
    var response = FIXTURE.response;
    var request = FIXTURE.request;
    var oidc = FIXTURE.oidc;
    
    it("bad response type  in request", function(){
        try{
            new OIDCAuthentication.ResponseValidator(request.bad, response.location_hash());
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.InvalidResponseTypeError).toBe(true);
        }
    });
    
    it("missing properties [id_token] in response", function(){
        var rV =  new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__id_token__location_hash());
        
        try{
            rV.validate(oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError).toBe(true);
        }
    });
    
    it("missing properties [access_token] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__access_token__location_hash());
        
        try{
            rV.validate(oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError).toBe(true);
        }
    });
    
    it("missing properties [token_type] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__token_type__location_hash());
        
        try{
            rV.validate(oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError).toBe(true);
        }
    });
    
    it("missing properties [state] in response", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request.good, response.missing_property__state__location_hash());
        
        try{
            rV.validate(oidc.client_certificate);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingPropertyError).toBe(true);
        }
    });
});

describe('OIDC Vaildator', function(){
    var id_token = FIXTURE.id_token;
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    var oidc = FIXTURE.oidc;
    
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
    
    it("validates the JWS Signature from the certificate (PEM)", function(){
        var status = rV.validate(oidc.client_certificate);
        
        expect(status.signatureVerified).toBe(true);
    });
    
    //Test we can validate a signature
    it("gets a payload from a token", function(){
        var token = rV.getPayload(id_token);
        
        expect(typeof token).toBe("object");
    });

    
});