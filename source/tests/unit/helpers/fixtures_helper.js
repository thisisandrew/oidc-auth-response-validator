/**
 * Fixtures for OIDC needed for OAuth Client
 */
var FIXTURE = FIXTURE || {};

(function(){
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
    
    oidc.client_certificate = "MIIDCzCCAfegAwIBAgIQnxu3IVjoELtKf4qVckvRKTAJBgUrDgMCHQUAMBUxEzARBgNVBAMTCmlkc3J2M3Rlc3QwHhcNMTQwOTE1MTEzMTQ0WhcNMTYwOTE0MjMwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyDXZz13Cq503ek3Y82Fd2nMf5AGvR0YoHymGuGitaVvfV3Quam7jSELuqe8UFSjn8kPG6Rmm";
    
    FIXTURE.oidc = oidc;
}());


(function(){
    var id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoic3NwIiwibmJmIjoxNDEyNzUyOTEzLCJleHAiOjE0MTI3NTMyNzMsIm5vbmNlIjoiMzM2NTgzMTQyNTExNjg4OTYiLCJpYXQiOjE0MTI3NTI5MTQsImF0X2hhc2giOiJibUtneVFhMmxjWi01TUhreU9TZVNRIiwic3ViIjoiZDQ0ZDRlMDAtZDkxNC00MDBhLWE5N2QtYjlkZDBhNTBhYTliIiwiYW1yIjoicGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MTI3NTI4NTgsImlkcCI6Imlkc3J2IiwibmFtZSI6IkRlZmF1bHQgQWRtaW5pc3RyYXRvciJ9.uerkTaDioK0Bd3XsGszjS8bVKnnCqk44lNd556btvelhPVa_xKxcuDuQ_vhC3eDcwKjzDTLWpKrkhJC62wLRnu1nsD8m-895hYasQROTLXBqfuXHJR0UZQ7hcoEkIgyid5j5mcVub0O7p0-Bh_VrOuszNexlTBTSgcUFNjGWGT3DKFqxdYVwFrNErtDx1TwKFoK3jdPa3gU7vhV1vbw2NY2KsHpm1nDY2muRtvi85Mq4G5KzAb1n6DGqo_msj8vFK5VFV6kKA9mPk2cT7Azfdmb3KpLJ-G-bfJOSxQmhNr6etLIN_0qdcyFEBryRjjAc-BeX3zayyTQ7-neeHdxrQw";
    
    FIXTURE.id_token = id_token;
}());

(function(){
    var request = {
        url: "https:\/\/saserver1\/vouch\/connect\/authorize?client_id=ssp&redirect_uri=http%3A%2F%2Fsaserver1%3A3000%2Fimplicit_flow_reponse.html&response_type=id_token%20token&scope=openid%20profile%20ssp&state=6909352776125815&nonce=13542218577036975",
        state: "6909352776125815",
        nonce: "13542218577036975",
        response_type: "id_token token"
    };
    
    FIXTURE.request = request;
}());

(function(){
    var response = "#id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoic3NwIiwibmJmIjoxNDEyNzU2NzQyLCJleHAiOjE0MTI3NTcxMDIsIm5vbmNlIjoiMTM1NDIyMTg1NzcwMzY5NzUiLCJpYXQiOjE0MTI3NTY3NDMsImF0X2hhc2giOiJrQi13blJ1ZS1weDJUbGJiQXVKa2VnIiwic3ViIjoiZDQ0ZDRlMDAtZDkxNC00MDBhLWE5N2QtYjlkZDBhNTBhYTliIiwiYW1yIjoicGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MTI3NTY3NDIsImlkcCI6Imlkc3J2IiwibmFtZSI6IkRlZmF1bHQgQWRtaW5pc3RyYXRvciJ9.jDerqBJAUt7AQxK1qkB-e1z_1TwL37x-75KQZY9yMVnMx3bPv_X6fV-XSeEJKOcp19jU2yOOlUCL4Ksh5RgfpeaxTcV0x2RQnbzJDBT1A7vS-G6xtGx8UubLFQi5F4KCcbnBplSABH0BUkTT2bJTJ5QuRB9DV3Dw-IcrkOeR3D6uyICx3rq8V0r_jRCgeIu3JZJugLb9O7zylOcjey7wqU-HcPsq--UFyvUEuz2v9RDhod4auQa2J2XU6LBN-n4PfAwFqFr9VrSTndN0wCoqDcSF18ljHwxWgh-GjS3td9A_oI_5XKFOk5MPEjdkAEo6u30PdyMyYZxLkfJcbmr1lw&access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imo5T05PRUdOdG5DcGpIZ3FxWk1GM1daSTFfSSJ9.eyJpc3MiOiJodHRwczovL3d3dy50aGlzaXNudW1lcm8uY29tL3ZvdWNoIiwiYXVkIjoiaHR0cHM6Ly93d3cudGhpc2lzbnVtZXJvLmNvbS92b3VjaC9yZXNvdXJjZXMiLCJuYmYiOjE0MTI3NTY3NDIsImV4cCI6MTQxMjc1NzEwMiwiY2xpZW50X2lkIjoic3NwIiwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSIsInNzcCJdLCJzdWIiOiJkNDRkNGUwMC1kOTE0LTQwMGEtYTk3ZC1iOWRkMGE1MGFhOWIiLCJhbXIiOiJwYXNzd29yZCIsImF1dGhfdGltZSI6MTQxMjc1Njc0MiwiaWRwIjoiaWRzcnYiLCJuYW1lIjoiRGVmYXVsdCBBZG1pbmlzdHJhdG9yIn0.pzxmR76YwI7HIfe2J1DYoOILUeWN1IRNXA2jt6_aQXemiQ2Lp4GOVOCgiFPyAX0ekyP_pljVV3N5yh-Lm0ULatY1jieqwWQrDV6cqYO6yz5dBST684Qp9DIViYiPMwAbVEKkpPlwBqOmxcAHzjzSXxnrkNXX2R1Tga0S-WkXKlBVw_Ukch3xWRjlFCc1Hg0naNydgipSrUbNmGc_6nrXRU_bZbOcmVWi6mVQi4oiKHNdYP6zsTOf2xt8TIl-p_qRG9BrNv7W43epx8xb1zzlA9Bpv0ytpO7dhBfy6TKdhOsPSxgle1VATXwVzwEkahkG5mashYi28gnmy61wG7r4jQ&token_type=Bearer&expires_in=360&scope=openid%20profile%20ssp&state=6909352776125815";
    
    FIXTURE.response = response;
}());
