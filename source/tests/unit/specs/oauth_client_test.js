describe('OAuth Client Factory', function () {
    'use strict';
    
    var client;
   
    beforeEach(function() {
        var oidc = FIXTURE.request.oidc; //Load OIDC conf etc from a fixture
        
        client = OAuthClientFactory(oidc);
    });
    
    it("provides an OAuth Client(client)", function() {
        expect(client instanceof OAuthClient).toBe(true);
    });
    
    it("client contains OIDC Discovery", function() {
        expect(client.oidc.conf).toBeDefined();
    });
    
    it("client contains an authorisation server url", function(){
        expect(client.url).toMatch("https://saserver1");
    });
    
    it("client has a certificate(PEM)", function(){
        expect(client.oidc.client_certificate).toBeDefined();
    });
});