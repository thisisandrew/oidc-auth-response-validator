describe('OAuth Client Factory', function () {
    'use strict';
    
    var client;
   
    beforeEach(function() {
        var oidc = FIXTURE.oidc; //Load OIDC conf etc from a fixture
        
        client = OAuthClientFactory(oidc);
    });
    
    it("provides an OAuth Client(client)", function() {
        expect(client instanceof OAuthClient).toBe(true);
    });
    
    it("client contains OIDC Discovery", function() {
        expect(client.discoveredConfiguration).toBeDefined();
    });
    
    it("client contains an authorisation server url", function(){
        expect(client.url).toMatch("https://saserver1");
    });
    
    it("client has a certificate(PEM)", function(){
        expect(client.certificate).toBeDefined();
    });
});