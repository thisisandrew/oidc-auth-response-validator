describe('OIDC Validator', function () {
    var id_token = FIXTURE.id_token;
    var request = FIXTURE.request;
    var response = FIXTURE.response;
    var oidc = FIXTURE.oidc;
    
    it("cannot be created with null request", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(null, response);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(null, response);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("cannot be created with undefined request", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(undefined, response);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(undefined, response);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("cannot be created with null response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request, null);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request, null);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("cannot be created with undefined response", function(){
        expect(function(){
            new OIDCAuthentication.ResponseValidator(request, undefined);
        }).toThrow();
        
        try{
            new OIDCAuthentication.ResponseValidator(request, undefined);
        } catch(e) {
            expect(e instanceof OIDCAuthentication.ResponseValidator.Errors.MissingParameterError).toBe(true);
        }
    });
    
    it("can be created with a valid parameters", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request, response);
        
        expect(rV instanceof OIDCAuthentication.ResponseValidator).toBe(true);
    });
    
    it("assigns correct flow from request.response_type ('id_token token' - > Implicit Flow)", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request, response);
        
        expect(rV.flow instanceof OIDCAuthentication.Flows.Implicit).toBe(true);
    });
    
    it("validates the JWS Signature from the certificate (PEM)", function(){
        var rV = new OIDCAuthentication.ResponseValidator(request, response);
        
        expect(function(){ rV.validate(oidc.client_certificate); }).toBe(true);
    });
});