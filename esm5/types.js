/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Additional options that can be passt to tryLogin.
 */
var /**
 * Additional options that can be passt to tryLogin.
 */
LoginOptions = /** @class */ (function () {
    function LoginOptions() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true.
         */
        this.preventClearHashAfterLogin = false;
    }
    return LoginOptions;
}());
/**
 * Additional options that can be passt to tryLogin.
 */
export { LoginOptions };
if (false) {
    /**
     * Is called, after a token has been received and
     * successfully validated.
     *
     * Deprecated:  Use property ``events`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.onTokenReceived;
    /**
     * Hook, to validate the received tokens.
     *
     * Deprecated:  Use property ``tokenValidationHandler`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.validationHandler;
    /**
     * Called when tryLogin detects that the auth server
     * included an error message into the hash fragment.
     *
     * Deprecated:  Use property ``events`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.onLoginError;
    /**
     * A custom hash fragment to be used instead of the
     * actual one. This is used for silent refreshes, to
     * pass the iframes hash fragment to this method.
     * @type {?}
     */
    LoginOptions.prototype.customHashFragment;
    /**
     * Set this to true to disable the oauth2 state
     * check which is a best practice to avoid
     * security attacks.
     * As OIDC defines a nonce check that includes
     * this, this can be set to true when only doing
     * OIDC.
     * @type {?}
     */
    LoginOptions.prototype.disableOAuth2StateCheck;
    /**
     * Normally, you want to clear your hash fragment after
     * the lib read the token(s) so that they are not displayed
     * anymore in the url. If not, set this to true.
     * @type {?}
     */
    LoginOptions.prototype.preventClearHashAfterLogin;
}
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
var /**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
OAuthLogger = /** @class */ (function () {
    function OAuthLogger() {
    }
    return OAuthLogger;
}());
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
export { OAuthLogger };
if (false) {
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.debug = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.info = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.log = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.warn = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.error = function (message, optionalParams) { };
}
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
var /**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
OAuthStorage = /** @class */ (function () {
    function OAuthStorage() {
    }
    return OAuthStorage;
}());
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
export { OAuthStorage };
if (false) {
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    OAuthStorage.prototype.getItem = function (key) { };
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    OAuthStorage.prototype.removeItem = function (key) { };
    /**
     * @abstract
     * @param {?} key
     * @param {?} data
     * @return {?}
     */
    OAuthStorage.prototype.setItem = function (key, data) { };
}
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
var /**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
ReceivedTokens = /** @class */ (function () {
    function ReceivedTokens() {
    }
    return ReceivedTokens;
}());
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
export { ReceivedTokens };
if (false) {
    /** @type {?} */
    ReceivedTokens.prototype.idToken;
    /** @type {?} */
    ReceivedTokens.prototype.accessToken;
    /** @type {?} */
    ReceivedTokens.prototype.idClaims;
    /** @type {?} */
    ReceivedTokens.prototype.state;
}
/**
 * Represents the parsed and validated id_token.
 * @record
 */
export function ParsedIdToken() { }
if (false) {
    /** @type {?} */
    ParsedIdToken.prototype.idToken;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenClaims;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenHeader;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenClaimsJson;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenHeaderJson;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenExpiresAt;
}
/**
 * Represents the response from the token endpoint
 * http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 * @record
 */
export function TokenResponse() { }
if (false) {
    /** @type {?} */
    TokenResponse.prototype.access_token;
    /** @type {?} */
    TokenResponse.prototype.id_token;
    /** @type {?} */
    TokenResponse.prototype.token_type;
    /** @type {?} */
    TokenResponse.prototype.expires_in;
    /** @type {?} */
    TokenResponse.prototype.refresh_token;
    /** @type {?} */
    TokenResponse.prototype.scope;
    /** @type {?|undefined} */
    TokenResponse.prototype.state;
}
/**
 * Represents the response from the user info endpoint
 * http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 * @record
 */
export function UserInfo() { }
if (false) {
    /** @type {?} */
    UserInfo.prototype.sub;
    /* Skipping unhandled member: [key: string]: any;*/
}
/**
 * Represents an OpenID Connect discovery document
 * @record
 */
export function OidcDiscoveryDoc() { }
if (false) {
    /** @type {?} */
    OidcDiscoveryDoc.prototype.issuer;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.authorization_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint_auth_methods_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint_auth_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.check_session_iframe;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.end_session_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.jwks_uri;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.registration_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.scopes_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.response_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.acr_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.response_modes_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.grant_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.subject_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_encryption_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_encryption_enc_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_encryption_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_encryption_enc_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.request_object_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.display_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claim_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claims_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claims_parameter_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.service_documentation;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.ui_locales_supported;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHlwZXMuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidHlwZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUdBOzs7O0lBQUE7Ozs7OztRQThDRSwrQkFBMEIsR0FBSSxLQUFLLENBQUM7SUFDdEMsQ0FBQztJQUFELG1CQUFDO0FBQUQsQ0FBQyxBQS9DRCxJQStDQzs7Ozs7Ozs7Ozs7OztJQXhDQyx1Q0FBMkQ7Ozs7Ozs7SUFPM0QseUNBQXFFOzs7Ozs7OztJQVFyRSxvQ0FBd0M7Ozs7Ozs7SUFPeEMsMENBQTRCOzs7Ozs7Ozs7O0lBVTVCLCtDQUFrQzs7Ozs7OztJQU9sQyxrREFBb0M7Ozs7Ozs7OztBQVN0Qzs7Ozs7Ozs7SUFBQTtJQU1BLENBQUM7SUFBRCxrQkFBQztBQUFELENBQUMsQUFORCxJQU1DOzs7Ozs7Ozs7Ozs7Ozs7O0lBTEMscUVBQThEOzs7Ozs7O0lBQzlELG9FQUE2RDs7Ozs7OztJQUM3RCxtRUFBNEQ7Ozs7Ozs7SUFDNUQsb0VBQTZEOzs7Ozs7O0lBQzdELHFFQUE4RDs7Ozs7Ozs7O0FBU2hFOzs7Ozs7OztJQUFBO0lBSUEsQ0FBQztJQUFELG1CQUFDO0FBQUQsQ0FBQyxBQUpELElBSUM7Ozs7Ozs7Ozs7Ozs7OztJQUhDLG9EQUE2Qzs7Ozs7O0lBQzdDLHVEQUF1Qzs7Ozs7OztJQUN2QywwREFBa0Q7Ozs7OztBQU9wRDs7Ozs7SUFBQTtJQUtBLENBQUM7SUFBRCxxQkFBQztBQUFELENBQUMsQUFMRCxJQUtDOzs7Ozs7OztJQUpDLGlDQUFnQjs7SUFDaEIscUNBQW9COztJQUNwQixrQ0FBa0I7O0lBQ2xCLCtCQUFlOzs7Ozs7QUFNakIsbUNBT0M7OztJQU5DLGdDQUFnQjs7SUFDaEIsc0NBQXNCOztJQUN0QixzQ0FBc0I7O0lBQ3RCLDBDQUEwQjs7SUFDMUIsMENBQTBCOztJQUMxQix5Q0FBeUI7Ozs7Ozs7QUFPM0IsbUNBUUM7OztJQVBDLHFDQUFxQjs7SUFDckIsaUNBQWlCOztJQUNqQixtQ0FBbUI7O0lBQ25CLG1DQUFtQjs7SUFDbkIsc0NBQXNCOztJQUN0Qiw4QkFBYzs7SUFDZCw4QkFBZTs7Ozs7OztBQU9qQiw4QkFHQzs7O0lBRkMsdUJBQVk7Ozs7Ozs7QUFPZCxzQ0E4QkM7OztJQTdCQyxrQ0FBZTs7SUFDZixrREFBK0I7O0lBQy9CLDBDQUF1Qjs7SUFDdkIsaUVBQWdEOztJQUNoRCw0RUFBMkQ7O0lBQzNELDZDQUEwQjs7SUFDMUIsZ0RBQTZCOztJQUM3QixnREFBNkI7O0lBQzdCLG9DQUFpQjs7SUFDakIsaURBQThCOztJQUM5Qiw0Q0FBMkI7O0lBQzNCLG9EQUFtQzs7SUFDbkMsZ0RBQStCOztJQUMvQixvREFBbUM7O0lBQ25DLGlEQUFnQzs7SUFDaEMsbURBQWtDOztJQUNsQyxpRUFBZ0Q7O0lBQ2hELG9FQUFtRDs7SUFDbkQsb0VBQW1EOztJQUNuRCxpRUFBZ0Q7O0lBQ2hELG9FQUFtRDs7SUFDbkQsb0VBQW1EOztJQUNuRCx1RUFBc0Q7O0lBQ3RELG9EQUFtQzs7SUFDbkMsaURBQWdDOztJQUNoQyw0Q0FBMkI7O0lBQzNCLHNEQUFvQzs7SUFDcEMsaURBQThCOztJQUM5QixnREFBK0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcclxuICogQWRkaXRpb25hbCBvcHRpb25zIHRoYXQgY2FuIGJlIHBhc3N0IHRvIHRyeUxvZ2luLlxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIExvZ2luT3B0aW9ucyB7XHJcbiAgLyoqXHJcbiAgICogSXMgY2FsbGVkLCBhZnRlciBhIHRva2VuIGhhcyBiZWVuIHJlY2VpdmVkIGFuZFxyXG4gICAqIHN1Y2Nlc3NmdWxseSB2YWxpZGF0ZWQuXHJcbiAgICpcclxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgb25Ub2tlblJlY2VpdmVkPzogKHJlY2VpdmVkVG9rZW5zOiBSZWNlaXZlZFRva2VucykgPT4gdm9pZDtcclxuXHJcbiAgLyoqXHJcbiAgICogSG9vaywgdG8gdmFsaWRhdGUgdGhlIHJlY2VpdmVkIHRva2Vucy5cclxuICAgKlxyXG4gICAqIERlcHJlY2F0ZWQ6ICBVc2UgcHJvcGVydHkgYGB0b2tlblZhbGlkYXRpb25IYW5kbGVyYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgdmFsaWRhdGlvbkhhbmRsZXI/OiAocmVjZWl2ZWRUb2tlbnM6IFJlY2VpdmVkVG9rZW5zKSA9PiBQcm9taXNlPGFueT47XHJcblxyXG4gIC8qKlxyXG4gICAqIENhbGxlZCB3aGVuIHRyeUxvZ2luIGRldGVjdHMgdGhhdCB0aGUgYXV0aCBzZXJ2ZXJcclxuICAgKiBpbmNsdWRlZCBhbiBlcnJvciBtZXNzYWdlIGludG8gdGhlIGhhc2ggZnJhZ21lbnQuXHJcbiAgICpcclxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXHJcbiAgICovXHJcbiAgb25Mb2dpbkVycm9yPzogKHBhcmFtczogb2JqZWN0KSA9PiB2b2lkO1xyXG5cclxuICAvKipcclxuICAgKiBBIGN1c3RvbSBoYXNoIGZyYWdtZW50IHRvIGJlIHVzZWQgaW5zdGVhZCBvZiB0aGVcclxuICAgKiBhY3R1YWwgb25lLiBUaGlzIGlzIHVzZWQgZm9yIHNpbGVudCByZWZyZXNoZXMsIHRvXHJcbiAgICogcGFzcyB0aGUgaWZyYW1lcyBoYXNoIGZyYWdtZW50IHRvIHRoaXMgbWV0aG9kLlxyXG4gICAqL1xyXG4gIGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZztcclxuXHJcbiAgLyoqXHJcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byBkaXNhYmxlIHRoZSBvYXV0aDIgc3RhdGVcclxuICAgKiBjaGVjayB3aGljaCBpcyBhIGJlc3QgcHJhY3RpY2UgdG8gYXZvaWRcclxuICAgKiBzZWN1cml0eSBhdHRhY2tzLlxyXG4gICAqIEFzIE9JREMgZGVmaW5lcyBhIG5vbmNlIGNoZWNrIHRoYXQgaW5jbHVkZXNcclxuICAgKiB0aGlzLCB0aGlzIGNhbiBiZSBzZXQgdG8gdHJ1ZSB3aGVuIG9ubHkgZG9pbmdcclxuICAgKiBPSURDLlxyXG4gICAqL1xyXG4gIGRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrPzogYm9vbGVhbjtcclxuXHJcbiAgLyoqXHJcbiAgICogTm9ybWFsbHksIHlvdSB3YW50IHRvIGNsZWFyIHlvdXIgaGFzaCBmcmFnbWVudCBhZnRlclxyXG4gICAqIHRoZSBsaWIgcmVhZCB0aGUgdG9rZW4ocykgc28gdGhhdCB0aGV5IGFyZSBub3QgZGlzcGxheWVkXHJcbiAgICogYW55bW9yZSBpbiB0aGUgdXJsLiBJZiBub3QsIHNldCB0aGlzIHRvIHRydWUuXHJcbiAgICovXHJcbiAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW4/ID0gZmFsc2U7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBEZWZpbmVzIHRoZSBsb2dnaW5nIGludGVyZmFjZSB0aGUgT0F1dGhTZXJ2aWNlIHVzZXNcclxuICogaW50ZXJuYWxseS4gSXMgY29tcGF0aWJsZSB3aXRoIHRoZSBgY29uc29sZWAgb2JqZWN0LFxyXG4gKiBidXQgeW91IGNhbiBwcm92aWRlIHlvdXIgb3duIGltcGxlbWVudGF0aW9uIGFzIHdlbGxcclxuICogdGhyb3VnaCBkZXBlbmRlbmN5IGluamVjdGlvbi5cclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aExvZ2dlciB7XHJcbiAgYWJzdHJhY3QgZGVidWcobWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcclxuICBhYnN0cmFjdCBpbmZvKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XHJcbiAgYWJzdHJhY3QgbG9nKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XHJcbiAgYWJzdHJhY3Qgd2FybihtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xyXG4gIGFic3RyYWN0IGVycm9yKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBEZWZpbmVzIGEgc2ltcGxlIHN0b3JhZ2UgdGhhdCBjYW4gYmUgdXNlZCBmb3JcclxuICogc3RvcmluZyB0aGUgdG9rZW5zIGF0IGNsaWVudCBzaWRlLlxyXG4gKiBJcyBjb21wYXRpYmxlIHRvIGxvY2FsU3RvcmFnZSBhbmQgc2Vzc2lvblN0b3JhZ2UsXHJcbiAqIGJ1dCB5b3UgY2FuIGFsc28gY3JlYXRlIHlvdXIgb3duIGltcGxlbWVudGF0aW9ucy5cclxuICovXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aFN0b3JhZ2Uge1xyXG4gIGFic3RyYWN0IGdldEl0ZW0oa2V5OiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsO1xyXG4gIGFic3RyYWN0IHJlbW92ZUl0ZW0oa2V5OiBzdHJpbmcpOiB2b2lkO1xyXG4gIGFic3RyYWN0IHNldEl0ZW0oa2V5OiBzdHJpbmcsIGRhdGE6IHN0cmluZyk6IHZvaWQ7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBSZXByZXNlbnRzIHRoZSByZWNlaXZlZCB0b2tlbnMsIHRoZSByZWNlaXZlZCBzdGF0ZVxyXG4gKiBhbmQgdGhlIHBhcnNlZCBjbGFpbXMgZnJvbSB0aGUgaWQtdG9rZW4uXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgUmVjZWl2ZWRUb2tlbnMge1xyXG4gIGlkVG9rZW46IHN0cmluZztcclxuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xyXG4gIGlkQ2xhaW1zPzogb2JqZWN0O1xyXG4gIHN0YXRlPzogc3RyaW5nO1xyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyB0aGUgcGFyc2VkIGFuZCB2YWxpZGF0ZWQgaWRfdG9rZW4uXHJcbiAqL1xyXG5leHBvcnQgaW50ZXJmYWNlIFBhcnNlZElkVG9rZW4ge1xyXG4gIGlkVG9rZW46IHN0cmluZztcclxuICBpZFRva2VuQ2xhaW1zOiBvYmplY3Q7XHJcbiAgaWRUb2tlbkhlYWRlcjogb2JqZWN0O1xyXG4gIGlkVG9rZW5DbGFpbXNKc29uOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkhlYWRlckpzb246IHN0cmluZztcclxuICBpZFRva2VuRXhwaXJlc0F0OiBudW1iZXI7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBSZXByZXNlbnRzIHRoZSByZXNwb25zZSBmcm9tIHRoZSB0b2tlbiBlbmRwb2ludFxyXG4gKiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1jb3JlLTFfMC5odG1sI1Rva2VuRW5kcG9pbnRcclxuICovXHJcbmV4cG9ydCBpbnRlcmZhY2UgVG9rZW5SZXNwb25zZSB7XHJcbiAgYWNjZXNzX3Rva2VuOiBzdHJpbmc7XHJcbiAgaWRfdG9rZW46IHN0cmluZzsgXHJcbiAgdG9rZW5fdHlwZTogc3RyaW5nO1xyXG4gIGV4cGlyZXNfaW46IG51bWJlcjtcclxuICByZWZyZXNoX3Rva2VuOiBzdHJpbmc7XHJcbiAgc2NvcGU6IHN0cmluZztcclxuICBzdGF0ZT86IHN0cmluZztcclxufVxyXG5cclxuLyoqXHJcbiAqIFJlcHJlc2VudHMgdGhlIHJlc3BvbnNlIGZyb20gdGhlIHVzZXIgaW5mbyBlbmRwb2ludFxyXG4gKiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1jb3JlLTFfMC5odG1sI1VzZXJJbmZvXHJcbiAqL1xyXG5leHBvcnQgaW50ZXJmYWNlIFVzZXJJbmZvIHtcclxuICBzdWI6IHN0cmluZztcclxuICBba2V5OiBzdHJpbmddOiBhbnk7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBSZXByZXNlbnRzIGFuIE9wZW5JRCBDb25uZWN0IGRpc2NvdmVyeSBkb2N1bWVudFxyXG4gKi9cclxuZXhwb3J0IGludGVyZmFjZSBPaWRjRGlzY292ZXJ5RG9jIHtcclxuICBpc3N1ZXI6IHN0cmluZztcclxuICBhdXRob3JpemF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgdG9rZW5fZW5kcG9pbnQ6IHN0cmluZztcclxuICB0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHVzZXJpbmZvX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgY2hlY2tfc2Vzc2lvbl9pZnJhbWU6IHN0cmluZztcclxuICBlbmRfc2Vzc2lvbl9lbmRwb2ludDogc3RyaW5nO1xyXG4gIGp3a3NfdXJpOiBzdHJpbmc7XHJcbiAgcmVnaXN0cmF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgc2NvcGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgcmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBhY3JfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgcmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBncmFudF90eXBlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHN1YmplY3RfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICByZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBkaXNwbGF5X3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIGNsYWltX3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgY2xhaW1zX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgY2xhaW1zX3BhcmFtZXRlcl9zdXBwb3J0ZWQ6IGJvb2xlYW47XHJcbiAgc2VydmljZV9kb2N1bWVudGF0aW9uOiBzdHJpbmc7XHJcbiAgdWlfbG9jYWxlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG59XHJcbiJdfQ==