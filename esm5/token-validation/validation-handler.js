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
var /**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
ValidationHandler = /** @class */ (function () {
    function ValidationHandler() {
    }
    return ValidationHandler;
}());
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
export { ValidationHandler };
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
var /**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
AbstractValidationHandler = /** @class */ (function () {
    function AbstractValidationHandler() {
    }
    /**
     * Validates the at_hash in an id_token against the received access_token.
     */
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    AbstractValidationHandler.prototype.validateAtHash = /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    function (params) {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var hashAlg, tokenHash, leftMostHalf, atHash, claimsAtHash;
            return tslib_1.__generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
                        return [4 /*yield*/, this.calcHash(params.accessToken, hashAlg)];
                    case 1:
                        tokenHash = _a.sent();
                        // sha256(accessToken, { asString: true });
                        leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
                        atHash = base64UrlEncode(leftMostHalf);
                        claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
                        if (atHash !== claimsAtHash) {
                            console.error('exptected at_hash: ' + atHash);
                            console.error('actual at_hash: ' + claimsAtHash);
                        }
                        return [2 /*return*/, atHash === claimsAtHash];
                }
            });
        });
    };
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @param jwtHeader the id_token's parsed header
     */
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    AbstractValidationHandler.prototype.inferHashAlgorithm = /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    function (jwtHeader) {
        /** @type {?} */
        var alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    };
    return AbstractValidationHandler;
}());
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
export { AbstractValidationHandler };
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLGtCQUFrQixDQUFDOzs7O0FBRW5ELHNDQU9DOzs7SUFOQyxtQ0FBZ0I7O0lBQ2hCLHVDQUFvQjs7SUFDcEIseUNBQXNCOztJQUN0Qix5Q0FBc0I7O0lBQ3RCLGdDQUFhOztJQUNiLG9DQUFnQzs7Ozs7OztBQU9sQzs7Ozs7O0lBQUE7SUFZQSxDQUFDO0lBQUQsd0JBQUM7QUFBRCxDQUFDLEFBWkQsSUFZQzs7Ozs7Ozs7Ozs7Ozs7SUFSQyxnRkFFZ0I7Ozs7Ozs7SUFLaEIsNkVBQXFGOzs7Ozs7OztBQVF2Rjs7Ozs7OztJQUFBO0lBb0RBLENBQUM7SUE5Q0M7O09BRUc7Ozs7OztJQUNHLGtEQUFjOzs7OztJQUFwQixVQUFxQixNQUF3Qjs7Ozs7O3dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7d0JBRTNDLHFCQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxPQUFPLENBQUMsRUFBQTs7d0JBQTVELFNBQVMsR0FBRyxTQUFnRDs7d0JBRTVELFlBQVksR0FBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQzt3QkFFeEQsTUFBTSxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUM7d0JBRXRDLFlBQVksR0FBRyxNQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDO3dCQUVwRSxJQUFJLE1BQU0sS0FBSyxZQUFZLEVBQUU7NEJBQzNCLE9BQU8sQ0FBQyxLQUFLLENBQUMscUJBQXFCLEdBQUcsTUFBTSxDQUFDLENBQUM7NEJBQzlDLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0JBQWtCLEdBQUcsWUFBWSxDQUFDLENBQUM7eUJBQ2xEO3dCQUVELHNCQUFPLE1BQU0sS0FBSyxZQUFZLEVBQUM7Ozs7S0FDaEM7SUFFRDs7Ozs7T0FLRzs7Ozs7Ozs7O0lBQ08sc0RBQWtCOzs7Ozs7OztJQUE1QixVQUE2QixTQUFpQjs7WUFDeEMsR0FBRyxHQUFXLFNBQVMsQ0FBQyxLQUFLLENBQUM7UUFFbEMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLEVBQUU7WUFDOUIsTUFBTSxJQUFJLEtBQUssQ0FBQywyQkFBMkIsR0FBRyxHQUFHLENBQUMsQ0FBQztTQUNwRDtRQUVELE9BQU8sTUFBTSxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDaEMsQ0FBQztJQVVILGdDQUFDO0FBQUQsQ0FBQyxBQXBERCxJQW9EQzs7Ozs7Ozs7Ozs7Ozs7O0lBaERDLHdGQUE2RTs7Ozs7Ozs7Ozs7SUErQzdFLHFGQUFxRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IGJhc2U2NFVybEVuY29kZSB9IGZyb20gXCIuLi9iYXNlNjQtaGVscGVyXCI7XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFZhbGlkYXRpb25QYXJhbXMge1xyXG4gIGlkVG9rZW46IHN0cmluZztcclxuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xyXG4gIGlkVG9rZW5IZWFkZXI6IG9iamVjdDtcclxuICBpZFRva2VuQ2xhaW1zOiBvYmplY3Q7XHJcbiAgandrczogb2JqZWN0O1xyXG4gIGxvYWRLZXlzOiAoKSA9PiBQcm9taXNlPG9iamVjdD47XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBJbnRlcmZhY2UgZm9yIEhhbmRsZXJzIHRoYXQgYXJlIGhvb2tlZCBpbiB0b1xyXG4gKiB2YWxpZGF0ZSB0b2tlbnMuXHJcbiAqL1xyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgVmFsaWRhdGlvbkhhbmRsZXIge1xyXG4gIC8qKlxyXG4gICAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZVNpZ25hdHVyZShcclxuICAgIHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXNcclxuICApOiBQcm9taXNlPGFueT47XHJcblxyXG4gIC8qKlxyXG4gICAqIFZhbGlkYXRlcyB0aGUgYXRfaGFzaCBpbiBhbiBpZF90b2tlbiBhZ2FpbnN0IHRoZSByZWNlaXZlZCBhY2Nlc3NfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGFic3RyYWN0IHZhbGlkYXRlQXRIYXNoKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+O1xyXG59XHJcblxyXG4vKipcclxuICogVGhpcyBhYnN0cmFjdCBpbXBsZW1lbnRhdGlvbiBvZiBWYWxpZGF0aW9uSGFuZGxlciBhbHJlYWR5IGltcGxlbWVudHNcclxuICogdGhlIG1ldGhvZCB2YWxpZGF0ZUF0SGFzaC4gSG93ZXZlciwgdG8gbWFrZSB1c2Ugb2YgaXQsXHJcbiAqIHlvdSBoYXZlIHRvIG92ZXJyaWRlIHRoZSBtZXRob2QgY2FsY0hhc2guXHJcbiAqL1xyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlciBpbXBsZW1lbnRzIFZhbGlkYXRpb25IYW5kbGVyIHtcclxuICAvKipcclxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cclxuICAgKi9cclxuICBhYnN0cmFjdCB2YWxpZGF0ZVNpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxhbnk+O1xyXG5cclxuICAvKipcclxuICAgKiBWYWxpZGF0ZXMgdGhlIGF0X2hhc2ggaW4gYW4gaWRfdG9rZW4gYWdhaW5zdCB0aGUgcmVjZWl2ZWQgYWNjZXNzX3Rva2VuLlxyXG4gICAqL1xyXG4gIGFzeW5jIHZhbGlkYXRlQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgbGV0IGhhc2hBbGcgPSB0aGlzLmluZmVySGFzaEFsZ29yaXRobShwYXJhbXMuaWRUb2tlbkhlYWRlcik7XHJcblxyXG4gICAgbGV0IHRva2VuSGFzaCA9IGF3YWl0IHRoaXMuY2FsY0hhc2gocGFyYW1zLmFjY2Vzc1Rva2VuLCBoYXNoQWxnKTsgLy8gc2hhMjU2KGFjY2Vzc1Rva2VuLCB7IGFzU3RyaW5nOiB0cnVlIH0pO1xyXG5cclxuICAgIGxldCBsZWZ0TW9zdEhhbGYgPSB0b2tlbkhhc2guc3Vic3RyKDAsIHRva2VuSGFzaC5sZW5ndGggLyAyKTtcclxuXHJcbiAgICBsZXQgYXRIYXNoID0gYmFzZTY0VXJsRW5jb2RlKGxlZnRNb3N0SGFsZik7XHJcblxyXG4gICAgbGV0IGNsYWltc0F0SGFzaCA9IHBhcmFtcy5pZFRva2VuQ2xhaW1zWydhdF9oYXNoJ10ucmVwbGFjZSgvPS9nLCAnJyk7XHJcblxyXG4gICAgaWYgKGF0SGFzaCAhPT0gY2xhaW1zQXRIYXNoKSB7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2V4cHRlY3RlZCBhdF9oYXNoOiAnICsgYXRIYXNoKTtcclxuICAgICAgY29uc29sZS5lcnJvcignYWN0dWFsIGF0X2hhc2g6ICcgKyBjbGFpbXNBdEhhc2gpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBhdEhhc2ggPT09IGNsYWltc0F0SGFzaDtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEluZmVycyB0aGUgbmFtZSBvZiB0aGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlXHJcbiAgICogZnJvbSB0aGUgYWxnIGZpZWxkIG9mIGFuIGlkX3Rva2VuLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIGp3dEhlYWRlciB0aGUgaWRfdG9rZW4ncyBwYXJzZWQgaGVhZGVyXHJcbiAgICovXHJcbiAgcHJvdGVjdGVkIGluZmVySGFzaEFsZ29yaXRobShqd3RIZWFkZXI6IG9iamVjdCk6IHN0cmluZyB7XHJcbiAgICBsZXQgYWxnOiBzdHJpbmcgPSBqd3RIZWFkZXJbJ2FsZyddO1xyXG5cclxuICAgIGlmICghYWxnLm1hdGNoKC9eLlNbMC05XXszfSQvKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FsZ29yaXRobSBub3Qgc3VwcG9ydGVkOiAnICsgYWxnKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gJ3NoYS0nICsgYWxnLnN1YnN0cigyKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENhbGN1bGF0ZXMgdGhlIGhhc2ggZm9yIHRoZSBwYXNzZWQgdmFsdWUgYnkgdXNpbmdcclxuICAgKiB0aGUgcGFzc2VkIGhhc2ggYWxnb3JpdGhtLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIHZhbHVlVG9IYXNoXHJcbiAgICogQHBhcmFtIGFsZ29yaXRobVxyXG4gICAqL1xyXG4gIHByb3RlY3RlZCBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcclxufVxyXG4iXX0=