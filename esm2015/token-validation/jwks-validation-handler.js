/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
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
export class JwksValidationHandler extends AbstractValidationHandler {
    constructor() {
        super(...arguments);
        /**
         * Allowed algorithms
         */
        this.allowedAlgorithms = [
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
        this.gracePeriodInSec = 600;
    }
    /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    validateSignature(params, retry = false) {
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
        let kid = params.idTokenHeader['kid'];
        /** @type {?} */
        let keys = params.jwks['keys'];
        /** @type {?} */
        let key;
        /** @type {?} */
        let alg = params.idTokenHeader['alg'];
        if (kid) {
            key = keys.find((/**
             * @param {?} k
             * @return {?}
             */
            k => k['kid'] === kid /* && k['use'] === 'sig' */));
        }
        else {
            /** @type {?} */
            let kty = this.alg2kty(alg);
            /** @type {?} */
            let matchingKeys = keys.filter((/**
             * @param {?} k
             * @return {?}
             */
            k => k['kty'] === kty && k['use'] === 'sig'));
            /*
                  if (matchingKeys.length == 0) {
                      let error = 'No matching key found.';
                      console.error(error);
                      return Promise.reject(error);
                  }*/
            if (matchingKeys.length > 1) {
                /** @type {?} */
                let error = 'More than one matching key found. Please specify a kid in the id_token header.';
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
            loadedKeys => (params.jwks = loadedKeys)))
                .then((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.validateSignature(params, true)));
        }
        if (!key && retry && !kid) {
            /** @type {?} */
            let error = 'No matching key found.';
            console.error(error);
            return Promise.reject(error);
        }
        if (!key && retry && kid) {
            /** @type {?} */
            let error = 'expected key not found in property jwks. ' +
                'This property is most likely loaded with the ' +
                'discovery document. ' +
                'Expected key id (kid): ' +
                kid;
            console.error(error);
            return Promise.reject(error);
        }
        /** @type {?} */
        let keyObj = rs.KEYUTIL.getKey(key);
        /** @type {?} */
        let validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        /** @type {?} */
        let isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
        if (isValid) {
            return Promise.resolve();
        }
        else {
            return Promise.reject('Signature not valid');
        }
    }
    /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    alg2kty(alg) {
        switch (alg.charAt(0)) {
            case 'R':
                return 'RSA';
            case 'E':
                return 'EC';
            default:
                throw new Error('Cannot infer kty from alg: ' + alg);
        }
    }
    /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    calcHash(valueToHash, algorithm) {
        /** @type {?} */
        let hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
        /** @type {?} */
        let result = hashAlg.digestString(valueToHash);
        /** @type {?} */
        let byteArrayAsString = this.toByteArrayAsString(result);
        return Promise.resolve(byteArrayAsString);
    }
    /**
     * @param {?} hexString
     * @return {?}
     */
    toByteArrayAsString(hexString) {
        /** @type {?} */
        let result = '';
        for (let i = 0; i < hexString.length; i += 2) {
            /** @type {?} */
            let hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            /** @type {?} */
            let num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    }
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUNMLHlCQUF5QixFQUUxQixNQUFNLHNCQUFzQixDQUFDOzs7QUFLOUIsT0FBTyxLQUFLLEVBQUUsTUFBTSxXQUFXLENBQUM7Ozs7Ozs7QUFRaEMsTUFBTSxPQUFPLHFCQUFzQixTQUFRLHlCQUF5QjtJQUFwRTs7Ozs7UUFJRSxzQkFBaUIsR0FBYTtZQUM1QixPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztTQUNSLENBQUM7Ozs7O1FBTUYscUJBQWdCLEdBQUcsR0FBRyxDQUFDO0lBc0h6QixDQUFDOzs7Ozs7SUFwSEMsaUJBQWlCLENBQUMsTUFBd0IsRUFBRSxLQUFLLEdBQUcsS0FBSztRQUN2RCxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU87WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDZCQUE2QixDQUFDLENBQUM7UUFDcEUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhO1lBQ3ZCLE1BQU0sSUFBSSxLQUFLLENBQUMsb0NBQW9DLENBQUMsQ0FBQztRQUN4RCxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUk7WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDBCQUEwQixDQUFDLENBQUM7UUFFOUQsSUFDRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDO1lBQ3BCLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ25DLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFB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QUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7Q0FDRjs7Ozs7O0lBeElDLGtEQVlFOzs7Ozs7SUFNRixpREFBdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1xyXG4gIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIsXHJcbiAgVmFsaWRhdGlvblBhcmFtc1xyXG59IGZyb20gJy4vdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuXHJcbi8vIGRlY2xhcmUgdmFyIHJlcXVpcmU6IGFueTtcclxuLy8gbGV0IHJzID0gcmVxdWlyZSgnanNyc2FzaWduJyk7XHJcblxyXG5pbXBvcnQgKiBhcyBycyBmcm9tICdqc3JzYXNpZ24nO1xyXG5cclxuLyoqXHJcbiAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuIGFnYWluc3Qgb25lXHJcbiAqIG9mIHRoZSBrZXlzIG9mIGFuIEpTT04gV2ViIEtleSBTZXQgKGp3a3MpLlxyXG4gKlxyXG4gKiBUaGlzIGp3a3MgY2FuIGJlIHByb3ZpZGVkIGJ5IHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQuXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgSndrc1ZhbGlkYXRpb25IYW5kbGVyIGV4dGVuZHMgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlciB7XHJcbiAgLyoqXHJcbiAgICogQWxsb3dlZCBhbGdvcml0aG1zXHJcbiAgICovXHJcbiAgYWxsb3dlZEFsZ29yaXRobXM6IHN0cmluZ1tdID0gW1xyXG4gICAgJ0hTMjU2JyxcclxuICAgICdIUzM4NCcsXHJcbiAgICAnSFM1MTInLFxyXG4gICAgJ1JTMjU2JyxcclxuICAgICdSUzM4NCcsXHJcbiAgICAnUlM1MTInLFxyXG4gICAgJ0VTMjU2JyxcclxuICAgICdFUzM4NCcsXHJcbiAgICAnUFMyNTYnLFxyXG4gICAgJ1BTMzg0JyxcclxuICAgICdQUzUxMidcclxuICBdO1xyXG5cclxuICAvKipcclxuICAgKiBUaW1lIHBlcmlvZCBpbiBzZWNvbmRzIHRoZSB0aW1lc3RhbXAgaW4gdGhlIHNpZ25hdHVyZSBjYW5cclxuICAgKiBkaWZmZXIgZnJvbSB0aGUgY3VycmVudCB0aW1lLlxyXG4gICAqL1xyXG4gIGdyYWNlUGVyaW9kSW5TZWMgPSA2MDA7XHJcblxyXG4gIHZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcywgcmV0cnkgPSBmYWxzZSk6IFByb21pc2U8YW55PiB7XHJcbiAgICBpZiAoIXBhcmFtcy5pZFRva2VuKSB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBpZFRva2VuIGV4cGVjdGVkIScpO1xyXG4gICAgaWYgKCFwYXJhbXMuaWRUb2tlbkhlYWRlcilcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdQYXJhbWV0ZXIgaWRUb2tlbkhhbmRsZXIgZXhwZWN0ZWQuJyk7XHJcbiAgICBpZiAoIXBhcmFtcy5qd2tzKSB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBqd2tzIGV4cGVjdGVkIScpO1xyXG5cclxuICAgIGlmIChcclxuICAgICAgIXBhcmFtcy5qd2tzWydrZXlzJ10gfHxcclxuICAgICAgIUFycmF5LmlzQXJyYXkocGFyYW1zLmp3a3NbJ2tleXMnXSkgfHxcclxuICAgICAgcGFyYW1zLmp3a3NbJ2tleXMnXS5sZW5ndGggPT09IDBcclxuICAgICkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FycmF5IGtleXMgaW4gandrcyBtaXNzaW5nIScpO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIGNvbnNvbGUuZGVidWcoJ3ZhbGlkYXRlU2lnbmF0dXJlOiByZXRyeScsIHJldHJ5KTtcclxuXHJcbiAgICBsZXQga2lkOiBzdHJpbmcgPSBwYXJhbXMuaWRUb2tlbkhlYWRlclsna2lkJ107XHJcbiAgICBsZXQga2V5czogb2JqZWN0W10gPSBwYXJhbXMuandrc1sna2V5cyddO1xyXG4gICAgbGV0IGtleTogb2JqZWN0O1xyXG5cclxuICAgIGxldCBhbGcgPSBwYXJhbXMuaWRUb2tlbkhlYWRlclsnYWxnJ107XHJcblxyXG4gICAgaWYgKGtpZCkge1xyXG4gICAgICBrZXkgPSBrZXlzLmZpbmQoayA9PiBrWydraWQnXSA9PT0ga2lkIC8qICYmIGtbJ3VzZSddID09PSAnc2lnJyAqLyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBsZXQga3R5ID0gdGhpcy5hbGcya3R5KGFsZyk7XHJcbiAgICAgIGxldCBtYXRjaGluZ0tleXMgPSBrZXlzLmZpbHRlcihcclxuICAgICAgICBrID0+IGtbJ2t0eSddID09PSBrdHkgJiYga1sndXNlJ10gPT09ICdzaWcnXHJcbiAgICAgICk7XHJcblxyXG4gICAgICAvKlxyXG4gICAgICAgICAgICBpZiAobWF0Y2hpbmdLZXlzLmxlbmd0aCA9PSAwKSB7XHJcbiAgICAgICAgICAgICAgICBsZXQgZXJyb3IgPSAnTm8gbWF0Y2hpbmcga2V5IGZvdW5kLic7XHJcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcclxuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XHJcbiAgICAgICAgICAgIH0qL1xyXG4gICAgICBpZiAobWF0Y2hpbmdLZXlzLmxlbmd0aCA+IDEpIHtcclxuICAgICAgICBsZXQgZXJyb3IgPVxyXG4gICAgICAgICAgJ01vcmUgdGhhbiBvbmUgbWF0Y2hpbmcga2V5IGZvdW5kLiBQbGVhc2Ugc3BlY2lmeSBhIGtpZCBpbiB0aGUgaWRfdG9rZW4gaGVhZGVyLic7XHJcbiAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcclxuICAgICAgfSBlbHNlIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID09PSAxKSB7XHJcbiAgICAgICAga2V5ID0gbWF0Y2hpbmdLZXlzWzBdO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFrZXkgJiYgIXJldHJ5ICYmIHBhcmFtcy5sb2FkS2V5cykge1xyXG4gICAgICByZXR1cm4gcGFyYW1zXHJcbiAgICAgICAgLmxvYWRLZXlzKClcclxuICAgICAgICAudGhlbihsb2FkZWRLZXlzID0+IChwYXJhbXMuandrcyA9IGxvYWRlZEtleXMpKVxyXG4gICAgICAgIC50aGVuKF8gPT4gdGhpcy52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMsIHRydWUpKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWtleSAmJiByZXRyeSAmJiAha2lkKSB7XHJcbiAgICAgIGxldCBlcnJvciA9ICdObyBtYXRjaGluZyBrZXkgZm91bmQuJztcclxuICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFrZXkgJiYgcmV0cnkgJiYga2lkKSB7XHJcbiAgICAgIGxldCBlcnJvciA9XHJcbiAgICAgICAgJ2V4cGVjdGVkIGtleSBub3QgZm91bmQgaW4gcHJvcGVydHkgandrcy4gJyArXHJcbiAgICAgICAgJ1RoaXMgcHJvcGVydHkgaXMgbW9zdCBsaWtlbHkgbG9hZGVkIHdpdGggdGhlICcgK1xyXG4gICAgICAgICdkaXNjb3ZlcnkgZG9jdW1lbnQuICcgK1xyXG4gICAgICAgICdFeHBlY3RlZCBrZXkgaWQgKGtpZCk6ICcgK1xyXG4gICAgICAgIGtpZDtcclxuXHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBrZXlPYmogPSBycy5LRVlVVElMLmdldEtleShrZXkpO1xyXG4gICAgbGV0IHZhbGlkYXRpb25PcHRpb25zID0ge1xyXG4gICAgICBhbGc6IHRoaXMuYWxsb3dlZEFsZ29yaXRobXMsXHJcbiAgICAgIGdyYWNlUGVyaW9kOiB0aGlzLmdyYWNlUGVyaW9kSW5TZWNcclxuICAgIH07XHJcbiAgICBsZXQgaXNWYWxpZCA9IHJzLktKVVIuandzLkpXUy52ZXJpZnlKV1QoXHJcbiAgICAgIHBhcmFtcy5pZFRva2VuLFxyXG4gICAgICBrZXlPYmosXHJcbiAgICAgIHZhbGlkYXRpb25PcHRpb25zXHJcbiAgICApO1xyXG5cclxuICAgIGlmIChpc1ZhbGlkKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdCgnU2lnbmF0dXJlIG5vdCB2YWxpZCcpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBhbGcya3R5KGFsZzogc3RyaW5nKSB7XHJcbiAgICBzd2l0Y2ggKGFsZy5jaGFyQXQoMCkpIHtcclxuICAgICAgY2FzZSAnUic6XHJcbiAgICAgICAgcmV0dXJuICdSU0EnO1xyXG4gICAgICBjYXNlICdFJzpcclxuICAgICAgICByZXR1cm4gJ0VDJztcclxuICAgICAgZGVmYXVsdDpcclxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBpbmZlciBrdHkgZnJvbSBhbGc6ICcgKyBhbGcpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgbGV0IGhhc2hBbGcgPSBuZXcgcnMuS0pVUi5jcnlwdG8uTWVzc2FnZURpZ2VzdCh7IGFsZzogYWxnb3JpdGhtIH0pO1xyXG4gICAgbGV0IHJlc3VsdCA9IGhhc2hBbGcuZGlnZXN0U3RyaW5nKHZhbHVlVG9IYXNoKTtcclxuICAgIGxldCBieXRlQXJyYXlBc1N0cmluZyA9IHRoaXMudG9CeXRlQXJyYXlBc1N0cmluZyhyZXN1bHQpO1xyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShieXRlQXJyYXlBc1N0cmluZyk7XHJcbiAgfVxyXG5cclxuICB0b0J5dGVBcnJheUFzU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XHJcbiAgICBsZXQgcmVzdWx0ID0gJyc7XHJcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGhleFN0cmluZy5sZW5ndGg7IGkgKz0gMikge1xyXG4gICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XHJcbiAgICAgIGxldCBudW0gPSBwYXJzZUludChoZXhEaWdpdCwgMTYpO1xyXG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShudW0pO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxuICB9XHJcbn0iXX0=