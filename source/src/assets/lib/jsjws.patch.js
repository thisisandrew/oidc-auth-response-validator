//apply patched function to instance of KJUR.jws.JWS
var patchJWS = function(instance){
    instance.parseJWS = function(sJWS, sigValNotNeeded) {
        if ((this.parsedJWS !== undefined) &&
            (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined))) {
            return;
        }
        if (sJWS.match(/^([^.]+)\.([^.]+)\.([^.]+)$/) == null) {
            throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
        }
        var b6Head = RegExp.$1;
        var b6Payload = RegExp.$2;
        var b6SigVal = RegExp.$3;
        var sSI = b6Head + "." + b6Payload;
        this.parsedJWS = {};
        this.parsedJWS.headB64U = b6Head;
        this.parsedJWS.payloadB64U = b6Payload;
        this.parsedJWS.sigvalB64U = b6SigVal;
        this.parsedJWS.si = sSI;
    
        if (!sigValNotNeeded) {
            var hSigVal = b64utohex(b6SigVal);
            var biSigVal = parseBigInt(hSigVal, 16);
            this.parsedJWS.sigvalH = hSigVal;
            this.parsedJWS.sigvalBI = biSigVal;
        }
    
        var sHead = b64utoutf8(b6Head);
        var sPayload = b64utoutf8(b6Payload);
        this.parsedJWS.headS = sHead;
        this.parsedJWS.payloadS = sPayload;
    
        if (!KJUR.jws.JWS.isSafeJSONString(sHead, this.parsedJWS, 'headP')){
            throw "malformed JSON string for JWS Head: " + sHead;
        }
    };
}