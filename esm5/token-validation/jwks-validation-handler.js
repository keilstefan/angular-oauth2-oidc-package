/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
import { AbstractValidationHandler } from './validation-handler';
// declare var require: any;
// let rs = require('jsrsasign');
import * as rs from 'jsrsasign';
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
var /**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
JwksValidationHandler = /** @class */ (function (_super) {
    tslib_1.__extends(JwksValidationHandler, _super);
    function JwksValidationHandler() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        /**
         * Allowed algorithms
         */
        _this.allowedAlgorithms = [
            'HS256',
            'HS384',
            'HS512',
            'RS256',
            'RS384',
            'RS512',
            'ES256',
            'ES384',
            'PS256',
            'PS384',
            'PS512'
        ];
        /**
         * Time period in seconds the timestamp in the signature can
         * differ from the current time.
         */
        _this.gracePeriodInSec = 600;
        return _this;
    }
    /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    JwksValidationHandler.prototype.validateSignature = /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    function (params, retry) {
        var _this = this;
        if (retry === void 0) { retry = false; }
        if (!params.idToken)
            throw new Error('Parameter idToken expected!');
        if (!params.idTokenHeader)
            throw new Error('Parameter idTokenHandler expected.');
        if (!params.jwks)
            throw new Error('Parameter jwks expected!');
        if (!params.jwks['keys'] ||
            !Array.isArray(params.jwks['keys']) ||
            params.jwks['keys'].length === 0) {
            throw new Error('Array keys in jwks missing!');
        }
        // console.debug('validateSignature: retry', retry);
        /** @type {?} */
        var kid = params.idTokenHeader['kid'];
        /** @type {?} */
        var keys = params.jwks['keys'];
        /** @type {?} */
        var key;
        /** @type {?} */
        var alg = params.idTokenHeader['alg'];
        if (kid) {
            key = keys.find((/**
             * @param {?} k
             * @return {?}
             */
            function (k) { return k['kid'] === kid; } /* && k['use'] === 'sig' */));
        }
        else {
            /** @type {?} */
            var kty_1 = this.alg2kty(alg);
            /** @type {?} */
            var matchingKeys = keys.filter((/**
             * @param {?} k
             * @return {?}
             */
            function (k) { return k['kty'] === kty_1 && k['use'] === 'sig'; }));
            /*
                  if (matchingKeys.length == 0) {
                      let error = 'No matching key found.';
                      console.error(error);
                      return Promise.reject(error);
                  }*/
            if (matchingKeys.length > 1) {
                /** @type {?} */
                var error = 'More than one matching key found. Please specify a kid in the id_token header.';
                console.error(error);
                return Promise.reject(error);
            }
            else if (matchingKeys.length === 1) {
                key = matchingKeys[0];
            }
        }
        if (!key && !retry && params.loadKeys) {
            return params
                .loadKeys()
                .then((/**
             * @param {?} loadedKeys
             * @return {?}
             */
            function (loadedKeys) { return (params.jwks = loadedKeys); }))
                .then((/**
             * @param {?} _
             * @return {?}
             */
            function (_) { return _this.validateSignature(params, true); }));
        }
        if (!key && retry && !kid) {
            /** @type {?} */
            var error = 'No matching key found.';
            console.error(error);
            return Promise.reject(error);
        }
        if (!key && retry && kid) {
            /** @type {?} */
            var error = 'expected key not found in property jwks. ' +
                'This property is most likely loaded with the ' +
                'discovery document. ' +
                'Expected key id (kid): ' +
                kid;
            console.error(error);
            return Promise.reject(error);
        }
        /** @type {?} */
        var keyObj = rs.KEYUTIL.getKey(key);
        /** @type {?} */
        var validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        /** @type {?} */
        var isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
        if (isValid) {
            return Promise.resolve();
        }
        else {
            return Promise.reject('Signature not valid');
        }
    };
    /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    JwksValidationHandler.prototype.alg2kty = /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    function (alg) {
        switch (alg.charAt(0)) {
            case 'R':
                return 'RSA';
            case 'E':
                return 'EC';
            default:
                throw new Error('Cannot infer kty from alg: ' + alg);
        }
    };
    /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    JwksValidationHandler.prototype.calcHash = /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    function (valueToHash, algorithm) {
        /** @type {?} */
        var hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
        /** @type {?} */
        var result = hashAlg.digestString(valueToHash);
        /** @type {?} */
        var byteArrayAsString = this.toByteArrayAsString(result);
        return Promise.resolve(byteArrayAsString);
    };
    /**
     * @param {?} hexString
     * @return {?}
     */
    JwksValidationHandler.prototype.toByteArrayAsString = /**
     * @param {?} hexString
     * @return {?}
     */
    function (hexString) {
        /** @type {?} */
        var result = '';
        for (var i = 0; i < hexString.length; i += 2) {
            /** @type {?} */
            var hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            /** @type {?} */
            var num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    };
    return JwksValidationHandler;
}(AbstractValidationHandler));
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
export { JwksValidationHandler };
if (false) {
    /**
     * Allowed algorithms
     * @type {?}
     */
    JwksValidationHandler.prototype.allowedAlgorithms;
    /**
     * Time period in seconds the timestamp in the signature can
     * differ from the current time.
     * @type {?}
     */
    JwksValidationHandler.prototype.gracePeriodInSec;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLE9BQU8sRUFDTCx5QkFBeUIsRUFFMUIsTUFBTSxzQkFBc0IsQ0FBQzs7O0FBSzlCLE9BQU8sS0FBSyxFQUFFLE1BQU0sV0FBVyxDQUFDOzs7Ozs7O0FBUWhDOzs7Ozs7O0lBQTJDLGlEQUF5QjtJQUFwRTtRQUFBLHFFQTRJQzs7OztRQXhJQyx1QkFBaUIsR0FBYTtZQUM1QixPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztTQUNSLENBQUM7Ozs7O1FBTUYsc0JBQWdCLEdBQUcsR0FBRyxDQUFDOztJQXNIekIsQ0FBQzs7Ozs7O0lBcEhDLGlEQUFpQjs7Ozs7SUFBakIsVUFBa0IsTUFBd0IsRUFBRSxLQUFhO1FBQXpELGlCQXVGQztRQXZGMkMsc0JBQUEsRUFBQSxhQUFhO1FBQ3ZELElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTztZQUFFLE1BQU0sSUFBSSxLQUFLLENBQUMsNkJBQTZCLENBQUMsQ0FBQztRQUNwRSxJQUFJLENBQUMsTUFBTSxDQUFDLGFBQWE7WUFDdkIsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFDO1FBQ3hELElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSTtZQUFFLE1BQU0sSUFBSSxLQUFLLENBQUMsMEJBQTBCLENBQUMsQ0FBQztRQUU5RCxJQUNFLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUM7WUFDcEIsQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFB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QUFHLENBQUMsQ0FBQzs7Z0JBQ3hELEdBQUcsR0FBRyxRQUFRLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQztZQUNoQyxNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNwQztRQUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7SUFDSCw0QkFBQztBQUFELENBQUMsQUE1SUQsQ0FBMkMseUJBQXlCLEdBNEluRTs7Ozs7Ozs7Ozs7OztJQXhJQyxrREFZRTs7Ozs7O0lBTUYsaURBQXVCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtcclxuICBBYnN0cmFjdFZhbGlkYXRpb25IYW5kbGVyLFxyXG4gIFZhbGlkYXRpb25QYXJhbXNcclxufSBmcm9tICcuL3ZhbGlkYXRpb24taGFuZGxlcic7XHJcblxyXG4vLyBkZWNsYXJlIHZhciByZXF1aXJlOiBhbnk7XHJcbi8vIGxldCBycyA9IHJlcXVpcmUoJ2pzcnNhc2lnbicpO1xyXG5cclxuaW1wb3J0ICogYXMgcnMgZnJvbSAnanNyc2FzaWduJztcclxuXHJcbi8qKlxyXG4gKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbiBhZ2FpbnN0IG9uZVxyXG4gKiBvZiB0aGUga2V5cyBvZiBhbiBKU09OIFdlYiBLZXkgU2V0IChqd2tzKS5cclxuICpcclxuICogVGhpcyBqd2tzIGNhbiBiZSBwcm92aWRlZCBieSB0aGUgZGlzY292ZXJ5IGRvY3VtZW50LlxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIEp3a3NWYWxpZGF0aW9uSGFuZGxlciBleHRlbmRzIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIge1xyXG4gIC8qKlxyXG4gICAqIEFsbG93ZWQgYWxnb3JpdGhtc1xyXG4gICAqL1xyXG4gIGFsbG93ZWRBbGdvcml0aG1zOiBzdHJpbmdbXSA9IFtcclxuICAgICdIUzI1NicsXHJcbiAgICAnSFMzODQnLFxyXG4gICAgJ0hTNTEyJyxcclxuICAgICdSUzI1NicsXHJcbiAgICAnUlMzODQnLFxyXG4gICAgJ1JTNTEyJyxcclxuICAgICdFUzI1NicsXHJcbiAgICAnRVMzODQnLFxyXG4gICAgJ1BTMjU2JyxcclxuICAgICdQUzM4NCcsXHJcbiAgICAnUFM1MTInXHJcbiAgXTtcclxuXHJcbiAgLyoqXHJcbiAgICogVGltZSBwZXJpb2QgaW4gc2Vjb25kcyB0aGUgdGltZXN0YW1wIGluIHRoZSBzaWduYXR1cmUgY2FuXHJcbiAgICogZGlmZmVyIGZyb20gdGhlIGN1cnJlbnQgdGltZS5cclxuICAgKi9cclxuICBncmFjZVBlcmlvZEluU2VjID0gNjAwO1xyXG5cclxuICB2YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMsIHJldHJ5ID0gZmFsc2UpOiBQcm9taXNlPGFueT4ge1xyXG4gICAgaWYgKCFwYXJhbXMuaWRUb2tlbikgdGhyb3cgbmV3IEVycm9yKCdQYXJhbWV0ZXIgaWRUb2tlbiBleHBlY3RlZCEnKTtcclxuICAgIGlmICghcGFyYW1zLmlkVG9rZW5IZWFkZXIpXHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGlkVG9rZW5IYW5kbGVyIGV4cGVjdGVkLicpO1xyXG4gICAgaWYgKCFwYXJhbXMuandrcykgdGhyb3cgbmV3IEVycm9yKCdQYXJhbWV0ZXIgandrcyBleHBlY3RlZCEnKTtcclxuXHJcbiAgICBpZiAoXHJcbiAgICAgICFwYXJhbXMuandrc1sna2V5cyddIHx8XHJcbiAgICAgICFBcnJheS5pc0FycmF5KHBhcmFtcy5qd2tzWydrZXlzJ10pIHx8XHJcbiAgICAgIHBhcmFtcy5qd2tzWydrZXlzJ10ubGVuZ3RoID09PSAwXHJcbiAgICApIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdBcnJheSBrZXlzIGluIGp3a3MgbWlzc2luZyEnKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBjb25zb2xlLmRlYnVnKCd2YWxpZGF0ZVNpZ25hdHVyZTogcmV0cnknLCByZXRyeSk7XHJcblxyXG4gICAgbGV0IGtpZDogc3RyaW5nID0gcGFyYW1zLmlkVG9rZW5IZWFkZXJbJ2tpZCddO1xyXG4gICAgbGV0IGtleXM6IG9iamVjdFtdID0gcGFyYW1zLmp3a3NbJ2tleXMnXTtcclxuICAgIGxldCBrZXk6IG9iamVjdDtcclxuXHJcbiAgICBsZXQgYWxnID0gcGFyYW1zLmlkVG9rZW5IZWFkZXJbJ2FsZyddO1xyXG5cclxuICAgIGlmIChraWQpIHtcclxuICAgICAga2V5ID0ga2V5cy5maW5kKGsgPT4ga1sna2lkJ10gPT09IGtpZCAvKiAmJiBrWyd1c2UnXSA9PT0gJ3NpZycgKi8pO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgbGV0IGt0eSA9IHRoaXMuYWxnMmt0eShhbGcpO1xyXG4gICAgICBsZXQgbWF0Y2hpbmdLZXlzID0ga2V5cy5maWx0ZXIoXHJcbiAgICAgICAgayA9PiBrWydrdHknXSA9PT0ga3R5ICYmIGtbJ3VzZSddID09PSAnc2lnJ1xyXG4gICAgICApO1xyXG5cclxuICAgICAgLypcclxuICAgICAgICAgICAgaWYgKG1hdGNoaW5nS2V5cy5sZW5ndGggPT0gMCkge1xyXG4gICAgICAgICAgICAgICAgbGV0IGVycm9yID0gJ05vIG1hdGNoaW5nIGtleSBmb3VuZC4nO1xyXG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xyXG4gICAgICAgICAgICB9Ki9cclxuICAgICAgaWYgKG1hdGNoaW5nS2V5cy5sZW5ndGggPiAxKSB7XHJcbiAgICAgICAgbGV0IGVycm9yID1cclxuICAgICAgICAgICdNb3JlIHRoYW4gb25lIG1hdGNoaW5nIGtleSBmb3VuZC4gUGxlYXNlIHNwZWNpZnkgYSBraWQgaW4gdGhlIGlkX3Rva2VuIGhlYWRlci4nO1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XHJcbiAgICAgIH0gZWxzZSBpZiAobWF0Y2hpbmdLZXlzLmxlbmd0aCA9PT0gMSkge1xyXG4gICAgICAgIGtleSA9IG1hdGNoaW5nS2V5c1swXTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmICgha2V5ICYmICFyZXRyeSAmJiBwYXJhbXMubG9hZEtleXMpIHtcclxuICAgICAgcmV0dXJuIHBhcmFtc1xyXG4gICAgICAgIC5sb2FkS2V5cygpXHJcbiAgICAgICAgLnRoZW4obG9hZGVkS2V5cyA9PiAocGFyYW1zLmp3a3MgPSBsb2FkZWRLZXlzKSlcclxuICAgICAgICAudGhlbihfID0+IHRoaXMudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zLCB0cnVlKSk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFrZXkgJiYgcmV0cnkgJiYgIWtpZCkge1xyXG4gICAgICBsZXQgZXJyb3IgPSAnTm8gbWF0Y2hpbmcga2V5IGZvdW5kLic7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICgha2V5ICYmIHJldHJ5ICYmIGtpZCkge1xyXG4gICAgICBsZXQgZXJyb3IgPVxyXG4gICAgICAgICdleHBlY3RlZCBrZXkgbm90IGZvdW5kIGluIHByb3BlcnR5IGp3a3MuICcgK1xyXG4gICAgICAgICdUaGlzIHByb3BlcnR5IGlzIG1vc3QgbGlrZWx5IGxvYWRlZCB3aXRoIHRoZSAnICtcclxuICAgICAgICAnZGlzY292ZXJ5IGRvY3VtZW50LiAnICtcclxuICAgICAgICAnRXhwZWN0ZWQga2V5IGlkIChraWQpOiAnICtcclxuICAgICAgICBraWQ7XHJcblxyXG4gICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcclxuICAgIH1cclxuXHJcbiAgICBsZXQga2V5T2JqID0gcnMuS0VZVVRJTC5nZXRLZXkoa2V5KTtcclxuICAgIGxldCB2YWxpZGF0aW9uT3B0aW9ucyA9IHtcclxuICAgICAgYWxnOiB0aGlzLmFsbG93ZWRBbGdvcml0aG1zLFxyXG4gICAgICBncmFjZVBlcmlvZDogdGhpcy5ncmFjZVBlcmlvZEluU2VjXHJcbiAgICB9O1xyXG4gICAgbGV0IGlzVmFsaWQgPSBycy5LSlVSLmp3cy5KV1MudmVyaWZ5SldUKFxyXG4gICAgICBwYXJhbXMuaWRUb2tlbixcclxuICAgICAga2V5T2JqLFxyXG4gICAgICB2YWxpZGF0aW9uT3B0aW9uc1xyXG4gICAgKTtcclxuXHJcbiAgICBpZiAoaXNWYWxpZCkge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoJ1NpZ25hdHVyZSBub3QgdmFsaWQnKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgYWxnMmt0eShhbGc6IHN0cmluZykge1xyXG4gICAgc3dpdGNoIChhbGcuY2hhckF0KDApKSB7XHJcbiAgICAgIGNhc2UgJ1InOlxyXG4gICAgICAgIHJldHVybiAnUlNBJztcclxuICAgICAgY2FzZSAnRSc6XHJcbiAgICAgICAgcmV0dXJuICdFQyc7XHJcbiAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgaW5mZXIga3R5IGZyb20gYWxnOiAnICsgYWxnKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGNhbGNIYXNoKHZhbHVlVG9IYXNoOiBzdHJpbmcsIGFsZ29yaXRobTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcclxuICAgIGxldCBoYXNoQWxnID0gbmV3IHJzLktKVVIuY3J5cHRvLk1lc3NhZ2VEaWdlc3QoeyBhbGc6IGFsZ29yaXRobSB9KTtcclxuICAgIGxldCByZXN1bHQgPSBoYXNoQWxnLmRpZ2VzdFN0cmluZyh2YWx1ZVRvSGFzaCk7XHJcbiAgICBsZXQgYnl0ZUFycmF5QXNTdHJpbmcgPSB0aGlzLnRvQnl0ZUFycmF5QXNTdHJpbmcocmVzdWx0KTtcclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoYnl0ZUFycmF5QXNTdHJpbmcpO1xyXG4gIH1cclxuXHJcbiAgdG9CeXRlQXJyYXlBc1N0cmluZyhoZXhTdHJpbmc6IHN0cmluZykge1xyXG4gICAgbGV0IHJlc3VsdCA9ICcnO1xyXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBoZXhTdHJpbmcubGVuZ3RoOyBpICs9IDIpIHtcclxuICAgICAgbGV0IGhleERpZ2l0ID0gaGV4U3RyaW5nLmNoYXJBdChpKSArIGhleFN0cmluZy5jaGFyQXQoaSArIDEpO1xyXG4gICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcclxuICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobnVtKTtcclxuICAgIH1cclxuICAgIHJldHVybiByZXN1bHQ7XHJcbiAgfVxyXG59Il19