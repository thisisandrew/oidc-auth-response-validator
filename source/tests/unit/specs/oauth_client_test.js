describe('OAuth Client Factory', function () {
    'use strict';
    
    var client;
   
    beforeEach(function() {
        var oidc_conf = FIXTURE.request.oidc_conf; //Load OIDC conf etc from a fixture
        
        client = OAuthClientFactory(oidc_conf);
    });
    
    it("provides an OAuth Client(client)", function() {
        expect(client instanceof OAuthClient).toBe(true);
    });
    
    it("client contains OIDC Discovery", function() {
        expect(client.oidc_conf).toBeDefined();
    });
    
    it("client contains an authorisation server url", function(){
        expect(client.url).toMatch("https://saserver1");
    });
    
    it("client has a certificate(PEM)", function(){
        expect(client.certificate).toBeDefined();
    });
});