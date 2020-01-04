/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
import { base64UrlEncode } from "../base64-helper";
/**
 * @record
 */
export function ValidationParams() { }
if (false) {
    /** @type {?} */
    ValidationParams.prototype.idToken;
    /** @type {?} */
    ValidationParams.prototype.accessToken;
    /** @type {?} */
    ValidationParams.prototype.idTokenHeader;
    /** @type {?} */
    ValidationParams.prototype.idTokenClaims;
    /** @type {?} */
    ValidationParams.prototype.jwks;
    /** @type {?} */
    ValidationParams.prototype.loadKeys;
}
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
export class ValidationHandler {
}
if (false) {
    /**
     * Validates the signature of an id_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    ValidationHandler.prototype.validateSignature = function (validationParams) { };
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    ValidationHandler.prototype.validateAtHash = function (validationParams) { };
}
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
export class AbstractValidationHandler {
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    validateAtHash(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            /** @type {?} */
            let hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
            /** @type {?} */
            let tokenHash = yield this.calcHash(params.accessToken, hashAlg);
            // sha256(accessToken, { asString: true });
            /** @type {?} */
            let leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
            /** @type {?} */
            let atHash = base64UrlEncode(leftMostHalf);
            /** @type {?} */
            let claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
            if (atHash !== claimsAtHash) {
                console.error('exptected at_hash: ' + atHash);
                console.error('actual at_hash: ' + claimsAtHash);
            }
            return atHash === claimsAtHash;
        });
    }
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    inferHashAlgorithm(jwtHeader) {
        /** @type {?} */
        let alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    }
}
if (false) {
    /**
     * Validates the signature of an id_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    AbstractValidationHandler.prototype.validateSignature = function (validationParams) { };
    /**
     * Calculates the hash for the passed value by using
     * the passed hash algorithm.
     *
     * @abstract
     * @protected
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    AbstractValidationHandler.prototype.calcHash = function (valueToHash, algorithm) { };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLGtCQUFrQixDQUFDOzs7O0FBRW5ELHNDQU9DOzs7SUFOQyxtQ0FBZ0I7O0lBQ2hCLHVDQUFvQjs7SUFDcEIseUNBQXNCOztJQUN0Qix5Q0FBc0I7O0lBQ3RCLGdDQUFhOztJQUNiLG9DQUFnQzs7Ozs7OztBQU9sQyxNQUFNLE9BQWdCLGlCQUFpQjtDQVl0Qzs7Ozs7Ozs7SUFSQyxnRkFFZ0I7Ozs7Ozs7SUFLaEIsNkVBQXFGOzs7Ozs7OztBQVF2RixNQUFNLE9BQWdCLHlCQUF5Qjs7Ozs7O0lBU3ZDLGNBQWMsQ0FBQyxNQUF3Qjs7O2dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7O2dCQUV2RCxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsT0FBTyxDQUFDOzs7Z0JBRTVELFlBQVksR0FBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQzs7Z0JBRXhELE1BQU0sR0FBRyxlQUFlLENBQUMsWUFBWSxDQUFDOztnQkFFdEMsWUFBWSxHQUFHLE1BQU0sQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUM7WUFFcEUsSUFBSSxNQUFNLEtBQUssWUFBWSxFQUFFO2dCQUMzQixPQUFPLENBQUMsS0FBSyxDQUFDLHFCQUFxQixHQUFHLE1BQU0sQ0FBQyxDQUFDO2dCQUM5QyxPQUFPLENBQUMsS0FBSyxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQyxDQUFDO2FBQ2xEO1lBRUQsT0FBTyxNQUFNLEtBQUssWUFBWSxDQUFDO1FBQ2pDLENBQUM7S0FBQTs7Ozs7Ozs7O0lBUVMsa0JBQWtCLENBQUMsU0FBaUI7O1lBQ3hDLEdBQUcsR0FBVyxTQUFTLENBQUMsS0FBSyxDQUFDO1FBRWxDLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkJBQTJCLEdBQUcsR0FBRyxDQUFDLENBQUM7U0FDcEQ7UUFFRCxPQUFPLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7Q0FVRjs7Ozs7Ozs7SUFoREMsd0ZBQTZFOzs7Ozs7Ozs7OztJQStDN0UscUZBQXFGIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgYmFzZTY0VXJsRW5jb2RlIH0gZnJvbSBcIi4uL2Jhc2U2NC1oZWxwZXJcIjtcclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgVmFsaWRhdGlvblBhcmFtcyB7XHJcbiAgaWRUb2tlbjogc3RyaW5nO1xyXG4gIGFjY2Vzc1Rva2VuOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkhlYWRlcjogb2JqZWN0O1xyXG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcclxuICBqd2tzOiBvYmplY3Q7XHJcbiAgbG9hZEtleXM6ICgpID0+IFByb21pc2U8b2JqZWN0PjtcclxufVxyXG5cclxuLyoqXHJcbiAqIEludGVyZmFjZSBmb3IgSGFuZGxlcnMgdGhhdCBhcmUgaG9va2VkIGluIHRvXHJcbiAqIHZhbGlkYXRlIHRva2Vucy5cclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBWYWxpZGF0aW9uSGFuZGxlciB7XHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGFic3RyYWN0IHZhbGlkYXRlU2lnbmF0dXJlKFxyXG4gICAgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtc1xyXG4gICk6IFByb21pc2U8YW55PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgYWJzdHJhY3QgdmFsaWRhdGVBdEhhc2godmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj47XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBUaGlzIGFic3RyYWN0IGltcGxlbWVudGF0aW9uIG9mIFZhbGlkYXRpb25IYW5kbGVyIGFscmVhZHkgaW1wbGVtZW50c1xyXG4gKiB0aGUgbWV0aG9kIHZhbGlkYXRlQXRIYXNoLiBIb3dldmVyLCB0byBtYWtlIHVzZSBvZiBpdCxcclxuICogeW91IGhhdmUgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCBjYWxjSGFzaC5cclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBBYnN0cmFjdFZhbGlkYXRpb25IYW5kbGVyIGltcGxlbWVudHMgVmFsaWRhdGlvbkhhbmRsZXIge1xyXG4gIC8qKlxyXG4gICAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuLlxyXG4gICAqL1xyXG4gIGFic3RyYWN0IHZhbGlkYXRlU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT47XHJcblxyXG4gIC8qKlxyXG4gICAqIFZhbGlkYXRlcyB0aGUgYXRfaGFzaCBpbiBhbiBpZF90b2tlbiBhZ2FpbnN0IHRoZSByZWNlaXZlZCBhY2Nlc3NfdG9rZW4uXHJcbiAgICovXHJcbiAgYXN5bmMgdmFsaWRhdGVBdEhhc2gocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICBsZXQgaGFzaEFsZyA9IHRoaXMuaW5mZXJIYXNoQWxnb3JpdGhtKHBhcmFtcy5pZFRva2VuSGVhZGVyKTtcclxuXHJcbiAgICBsZXQgdG9rZW5IYXNoID0gYXdhaXQgdGhpcy5jYWxjSGFzaChwYXJhbXMuYWNjZXNzVG9rZW4sIGhhc2hBbGcpOyAvLyBzaGEyNTYoYWNjZXNzVG9rZW4sIHsgYXNTdHJpbmc6IHRydWUgfSk7XHJcblxyXG4gICAgbGV0IGxlZnRNb3N0SGFsZiA9IHRva2VuSGFzaC5zdWJzdHIoMCwgdG9rZW5IYXNoLmxlbmd0aCAvIDIpO1xyXG5cclxuICAgIGxldCBhdEhhc2ggPSBiYXNlNjRVcmxFbmNvZGUobGVmdE1vc3RIYWxmKTtcclxuXHJcbiAgICBsZXQgY2xhaW1zQXRIYXNoID0gcGFyYW1zLmlkVG9rZW5DbGFpbXNbJ2F0X2hhc2gnXS5yZXBsYWNlKC89L2csICcnKTtcclxuXHJcbiAgICBpZiAoYXRIYXNoICE9PSBjbGFpbXNBdEhhc2gpIHtcclxuICAgICAgY29uc29sZS5lcnJvcignZXhwdGVjdGVkIGF0X2hhc2g6ICcgKyBhdEhhc2gpO1xyXG4gICAgICBjb25zb2xlLmVycm9yKCdhY3R1YWwgYXRfaGFzaDogJyArIGNsYWltc0F0SGFzaCk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGF0SGFzaCA9PT0gY2xhaW1zQXRIYXNoO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogSW5mZXJzIHRoZSBuYW1lIG9mIHRoZSBoYXNoIGFsZ29yaXRobSB0byB1c2VcclxuICAgKiBmcm9tIHRoZSBhbGcgZmllbGQgb2YgYW4gaWRfdG9rZW4uXHJcbiAgICpcclxuICAgKiBAcGFyYW0gand0SGVhZGVyIHRoZSBpZF90b2tlbidzIHBhcnNlZCBoZWFkZXJcclxuICAgKi9cclxuICBwcm90ZWN0ZWQgaW5mZXJIYXNoQWxnb3JpdGhtKGp3dEhlYWRlcjogb2JqZWN0KTogc3RyaW5nIHtcclxuICAgIGxldCBhbGc6IHN0cmluZyA9IGp3dEhlYWRlclsnYWxnJ107XHJcblxyXG4gICAgaWYgKCFhbGcubWF0Y2goL14uU1swLTldezN9JC8pKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxnb3JpdGhtIG5vdCBzdXBwb3J0ZWQ6ICcgKyBhbGcpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAnc2hhLScgKyBhbGcuc3Vic3RyKDIpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2FsY3VsYXRlcyB0aGUgaGFzaCBmb3IgdGhlIHBhc3NlZCB2YWx1ZSBieSB1c2luZ1xyXG4gICAqIHRoZSBwYXNzZWQgaGFzaCBhbGdvcml0aG0uXHJcbiAgICpcclxuICAgKiBAcGFyYW0gdmFsdWVUb0hhc2hcclxuICAgKiBAcGFyYW0gYWxnb3JpdGhtXHJcbiAgICovXHJcbiAgcHJvdGVjdGVkIGFic3RyYWN0IGNhbGNIYXNoKHZhbHVlVG9IYXNoOiBzdHJpbmcsIGFsZ29yaXRobTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+O1xyXG59XHJcbiJdfQ==