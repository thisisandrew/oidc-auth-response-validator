/**
 * Fixtures for OIDC needed for OAuth Client
 */
var FIXTURE = FIXTURE || {};

(function(){
    /**
     * An oidc configuration fixture
     */
    var oidc = {};
    
    oidc.conf = {
        issuer: "https://www.thisisnumero.com/vouch",
        jwks_uri: "https://saserver1/vouch/.well-known/jwks",
        authorization_endpoint: "https://saserver1/vouch/connect/authorize",
        token_endpoint: "https://saserver1/vouch/connect/token",
        userinfo_endpoint: "https://saserver1/vouch/connect/userinfo",
        end_session_endpoint: "https://saserver1/vouch/connect/endsession",
        scopes_supported: [
            "openid",
            "profile",
            "email",
            "api",
            "ego",
            "ssp"
        ],
        response_types_supported: [
            "code",
            "token",
            "id_token",
            "id_token token"
        ],
        response_modes_supported: [
            "form_post",
            "query",
            "fragment"
        ],
        grant_types_supported: [
            "authorization_code",
            "client_credentials",
            "password",
            "implicit"
        ],
        subject_types_support: [
            "pairwise",
            "public"
        ],
        id_token_signing_alg_values_supported: "RS256"
    };
    
    oidc.client_certificate = "MIIDCzCCAfegAwIBAgIQnxu3IVjoELtKf4qVckvRKTAJBgUrDgMCHQUAMBUxEzARBgNVBAMTCmlkc3J2M3Rlc3QwHhcNMTQwOTE1MTEzMTQ0WhcNMTYwOTE0MjMwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyDXZz13Cq503ek3Y82Fd2nMf5AGvR0YoHymGuGitaVvfV3Quam7jSELuqe8UFSjn8kPG6Rmm+qVSFTj70lKKn+w6qQUEOADmNzYY9MqfZKOuopswllF+uYhw7zhAb9v9XqfNWGCbRb4vIGV5GhfetIsuL6vIMRdLR1aQWeiZyz2yIaiVFKh+GyR0bIYWswvSptN5A1fRSuvqVnVYYWhhtDla/4DV1+Gr+yBt0f1zD0M0zZjX2o7Vj8gFN0gDqhSIRHq1QZ9CHEy3gpB53zeOh+rhSMdRpvNtmJ7NJpIlCtsXyO48jPFrxU6n6mt+SmeWCtO86MAgwUIVG1wdTLqVewIDAQABo18wXTATBgNVHSUEDDAKBggrBgEFBQcDAjBGBgNVHQEEPzA9gBBF9TrzBSBzqtu6JmPqM5zjoRcwFTETMBEGA1UEAxMKaWRzcnYzdGVzdIIQnxu3IVjoELtKf4qVckvRKTAJBgUrDgMCHQUAA4IBAQAdWI/r8UgKuk/IglEB9BkU4ZuowK40vfap0FH/TrHKGwTbQj3f4nT066w59a6FyLvGNoDxDd6enAlN3inV6lusK364ydEWe8wpDO2AZC3Dfh5k6qaWyVcWoOH2EA6g6fikIlEMNPHo3pDyP3551APBsvaT+Sx896Po2w1xJvgtm2lfOzhX3jZCcVXN0lDXWJM7f5TCiQ9yw6LW1aZPfRcWC3H7YRQ9ZIK2e2kqQMFBWnhwI25WtNQM/Y23zHXqE8euxmgMhzIo6TiXww1D0etFhXi/3mbtLniIcj14kNR6hrz18z6p3pw7Yl7Be5yS6Iv2a3Wj4Xah0b33O5wrrh7X";
    //FIXTURE.oidc = oidc;


    /**
     * An Authentication request (OAuth 2.0)
     */
    var request = {
        url: "https:\/\/saserver1\/vouch\/connect\/authorize?client_id=ssp&redirect_uri=http%3A%2F%2Fsaserver1%3A3000%2Fimplicit_flow_reponse.html&response_type=id_token%20token&scope=openid%20profile%20ssp&state=6909352776125815&nonce=13542218577036975",
        client_id: "ssp",
        state: "6909352776125815",
        nonce: "13542218577036975",
        response_type: "id_token token",
        oidc: oidc
    };
    
    request.good = {
        url: request.url,
        client_id: request.client_id,
        state: request.state,
        nonce: request.nonce,
        response_type: request.response_type,
        oidc: oidc
    };
    
    request.bad = {
        url: "NEVER_TESTED",
        client_id: "BAD_CLIENT_ID",
        state: "BAD_STATE",
        nonce: "BAD_NONCE",
        response_type: "BAD_RESPONSE_TYPE",
        oidc: oidc
    }
    FIXTURE.request = request;


    /**
     * A well formed id_token - Expired
     * Signed with the above oidc.client_certificate
     * Not from the below response
     */
    var id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoic3NwIiwibmJmIjoxNDEyNzUyOTEzLCJleHAiOjE0MTI3NTMyNzMsIm5vbmNlIjoiMzM2NTgzMTQyNTExNjg4OTYiLCJpYXQiOjE0MTI3NTI5MTQsImF0X2hhc2giOiJibUtneVFhMmxjWi01TUhreU9TZVNRIiwic3ViIjoiZDQ0ZDRlMDAtZDkxNC00MDBhLWE5N2QtYjlkZDBhNTBhYTliIiwiYW1yIjoicGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MTI3NTI4NTgsImlkcCI6Imlkc3J2IiwibmFtZSI6IkRlZmF1bHQgQWRtaW5pc3RyYXRvciJ9.uerkTaDioK0Bd3XsGszjS8bVKnnCqk44lNd556btvelhPVa_xKxcuDuQ_vhC3eDcwKjzDTLWpKrkhJC62wLRnu1nsD8m-895hYasQROTLXBqfuXHJR0UZQ7hcoEkIgyid5j5mcVub0O7p0-Bh_VrOuszNexlTBTSgcUFNjGWGT3DKFqxdYVwFrNErtDx1TwKFoK3jdPa3gU7vhV1vbw2NY2KsHpm1nDY2muRtvi85Mq4G5KzAb1n6DGqo_msj8vFK5VFV6kKA9mPk2cT7Azfdmb3KpLJ-G-bfJOSxQmhNr6etLIN_0qdcyFEBryRjjAc-BeX3zayyTQ7-neeHdxrQw";
    FIXTURE.id_token = id_token;
    
    

    /**
     * A well formed Authentication response based on the request.good above
     * id_token and access_token signed with the oidc.client_certificate
     */
    var response = {};
    response.id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoic3NwIiwibmJmIjoxNDEyNzU2NzQyLCJleHAiOjE0MTI3NTcxMDIsIm5vbmNlIjoiMTM1NDIyMTg1NzcwMzY5NzUiLCJpYXQiOjE0MTI3NTY3NDMsImF0X2hhc2giOiJrQi13blJ1ZS1weDJUbGJiQXVKa2VnIiwic3ViIjoiZDQ0ZDRlMDAtZDkxNC00MDBhLWE5N2QtYjlkZDBhNTBhYTliIiwiYW1yIjoicGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MTI3NTY3NDIsImlkcCI6Imlkc3J2IiwibmFtZSI6IkRlZmF1bHQgQWRtaW5pc3RyYXRvciJ9.jDerqBJAUt7AQxK1qkB-e1z_1TwL37x-75KQZY9yMVnMx3bPv_X6fV-XSeEJKOcp19jU2yOOlUCL4Ksh5RgfpeaxTcV0x2RQnbzJDBT1A7vS-G6xtGx8UubLFQi5F4KCcbnBplSABH0BUkTT2bJTJ5QuRB9DV3Dw-IcrkOeR3D6uyICx3rq8V0r_jRCgeIu3JZJugLb9O7zylOcjey7wqU-HcPsq--UFyvUEuz2v9RDhod4auQa2J2XU6LBN-n4PfAwFqFr9VrSTndN0wCoqDcSF18ljHwxWgh-GjS3td9A_oI_5XKFOk5MPEjdkAEo6u30PdyMyYZxLkfJcbmr1lw";
    response.access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoiaHR0cHM6Ly93d3cudGhpc2lzbnVtZXJvLmNvbS92b3VjaC9yZXNvdXJjZXMiLCJuYmYiOjE0MTI3NTY3NDIsImV4cCI6MTQxMjc1NzEwMiwiY2xpZW50X2lkIjoic3NwIiwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSIsInNzcCJdLCJzdWIiOiJkNDRkNGUwMC1kOTE0LTQwMGEtYTk3ZC1iOWRkMGE1MGFhOWIiLCJhbXIiOiJwYXNzd29yZCIsImF1dGhfdGltZSI6MTQxMjc1Njc0MiwiaWRwIjoiaWRzcnYiLCJuYW1lIjoiRGVmYXVsdCBBZG1pbmlzdHJhdG9yIn0.pzxmR76YwI7HIfe2J1DYoOILUeWN1IRNXA2jt6_aQXemiQ2Lp4GOVOCgiFPyAX0ekyP_pljVV3N5yh-Lm0ULatY1jieqwWQrDV6cqYO6yz5dBST684Qp9DIViYiPMwAbVEKkpPlwBqOmxcAHzjzSXxnrkNXX2R1Tga0S-WkXKlBVw_Ukch3xWRjlFCc1Hg0naNydgipSrUbNmGc_6nrXRU_bZbOcmVWi6mVQi4oiKHNdYP6zsTOf2xt8TIl-p_qRG9BrNv7W43epx8xb1zzlA9Bpv0ytpO7dhBfy6TKdhOsPSxgle1VATXwVzwEkahkG5mashYi28gnmy61wG7r4jQ";
    response.token_type = "Bearer";
    response.expires_in = "360";
    response.scope = "openid%20profile%20ssp";
    response.state = "6909352776125815";

    response.location_hash = function(){
        return "#id_token=" + this.id_token + "&access_token=" + this.access_token + "&token_type=" + this.token_type + "&expires_in=" + this.expires_in + "&scope=" + this.scope + "&state=" + this.state;
    };
    
    response.bad_location_hash = function(){
        return "#id_token=" + this.id_token + "&access_token=" + this.access_token + "&token_type=" + "BAD_TOKEN_TYPE" + "&expires_in=" + this.expires_in + "&scope=" + "BAD_SCOPE" + "&state=" + "BAD_STATE";
    };
    
    response.missing_property__id_token__location_hash = function(){
        return "#access_token=" + this.access_token + "&token_type=" + this.token_type + "&expires_in=" + this.expires_in + "&scope=" + this.scope + "&state=" + this.state;
    };
    
    response.missing_property__access_token__location_hash = function(){
        return "#id_token=" + this.id_token + "&token_type=" + this.token_type + "&expires_in=" + this.expires_in + "&scope=" + this.scope + "&state=" + this.state;
    };
    
    response.missing_property__token_type__location_hash = function(){
        return "#id_token=" + this.id_token + "&access_token=" + this.access_token + "&expires_in=" + this.expires_in + "&scope=" + this.scope + "&state=" + this.state;
    };
    
    response.missing_property__state__location_hash = function(){
        return "#id_token=" + this.id_token + "&access_token=" + this.access_token + "&token_type=" + this.token_type + "&expires_in=" + this.expires_in + "&scope=" + this.scope;
    };
    FIXTURE.response = response;
}());
