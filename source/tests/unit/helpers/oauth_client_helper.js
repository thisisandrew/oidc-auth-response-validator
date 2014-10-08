//Generate a mock OAuth Client (inject the oidc discovery dependency)
var mock_client_factory = function(oidc){
    var client = new OAuthClient(oidc.authorization_endpoint);
    client.discoveredConfiguration = oidc;
    
    return client;
}

