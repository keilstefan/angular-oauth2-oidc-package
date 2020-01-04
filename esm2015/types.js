/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Additional options that can be passt to tryLogin.
 */
export class LoginOptions {
    constructor() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true.
         */
        this.preventClearHashAfterLogin = false;
    }
}
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
export class OAuthLogger {
}
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
export class OAuthStorage {
}
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
export class ReceivedTokens {
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHlwZXMuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidHlwZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUdBLE1BQU0sT0FBTyxZQUFZO0lBQXpCOzs7Ozs7UUE4Q0UsK0JBQTBCLEdBQUksS0FBSyxDQUFDO0lBQ3RDLENBQUM7Q0FBQTs7Ozs7Ozs7O0lBeENDLHVDQUEyRDs7Ozs7OztJQU8zRCx5Q0FBcUU7Ozs7Ozs7O0lBUXJFLG9DQUF3Qzs7Ozs7OztJQU94QywwQ0FBNEI7Ozs7Ozs7Ozs7SUFVNUIsK0NBQWtDOzs7Ozs7O0lBT2xDLGtEQUFvQzs7Ozs7Ozs7O0FBU3RDLE1BQU0sT0FBZ0IsV0FBVztDQU1oQzs7Ozs7Ozs7SUFMQyxxRUFBOEQ7Ozs7Ozs7SUFDOUQsb0VBQTZEOzs7Ozs7O0lBQzdELG1FQUE0RDs7Ozs7OztJQUM1RCxvRUFBNkQ7Ozs7Ozs7SUFDN0QscUVBQThEOzs7Ozs7Ozs7QUFTaEUsTUFBTSxPQUFnQixZQUFZO0NBSWpDOzs7Ozs7O0lBSEMsb0RBQTZDOzs7Ozs7SUFDN0MsdURBQXVDOzs7Ozs7O0lBQ3ZDLDBEQUFrRDs7Ozs7O0FBT3BELE1BQU0sT0FBTyxjQUFjO0NBSzFCOzs7SUFKQyxpQ0FBZ0I7O0lBQ2hCLHFDQUFvQjs7SUFDcEIsa0NBQWtCOztJQUNsQiwrQkFBZTs7Ozs7O0FBTWpCLG1DQU9DOzs7SUFOQyxnQ0FBZ0I7O0lBQ2hCLHNDQUFzQjs7SUFDdEIsc0NBQXNCOztJQUN0QiwwQ0FBMEI7O0lBQzFCLDBDQUEwQjs7SUFDMUIseUNBQXlCOzs7Ozs7O0FBTzNCLG1DQVFDOzs7SUFQQyxxQ0FBcUI7O0lBQ3JCLGlDQUFpQjs7SUFDakIsbUNBQW1COztJQUNuQixtQ0FBbUI7O0lBQ25CLHNDQUFzQjs7SUFDdEIsOEJBQWM7O0lBQ2QsOEJBQWU7Ozs7Ozs7QUFPakIsOEJBR0M7OztJQUZDLHVCQUFZOzs7Ozs7O0FBT2Qsc0NBOEJDOzs7SUE3QkMsa0NBQWU7O0lBQ2Ysa0RBQStCOztJQUMvQiwwQ0FBdUI7O0lBQ3ZCLGlFQUFnRDs7SUFDaEQsNEVBQTJEOztJQUMzRCw2Q0FBMEI7O0lBQzFCLGdEQUE2Qjs7SUFDN0IsZ0RBQTZCOztJQUM3QixvQ0FBaUI7O0lBQ2pCLGlEQUE4Qjs7SUFDOUIsNENBQTJCOztJQUMzQixvREFBbUM7O0lBQ25DLGdEQUErQjs7SUFDL0Isb0RBQW1DOztJQUNuQyxpREFBZ0M7O0lBQ2hDLG1EQUFrQzs7SUFDbEMsaUVBQWdEOztJQUNoRCxvRUFBbUQ7O0lBQ25ELG9FQUFtRDs7SUFDbkQsaUVBQWdEOztJQUNoRCxvRUFBbUQ7O0lBQ25ELG9FQUFtRDs7SUFDbkQsdUVBQXNEOztJQUN0RCxvREFBbUM7O0lBQ25DLGlEQUFnQzs7SUFDaEMsNENBQTJCOztJQUMzQixzREFBb0M7O0lBQ3BDLGlEQUE4Qjs7SUFDOUIsZ0RBQStCIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXHJcbiAqIEFkZGl0aW9uYWwgb3B0aW9ucyB0aGF0IGNhbiBiZSBwYXNzdCB0byB0cnlMb2dpbi5cclxuICovXHJcbmV4cG9ydCBjbGFzcyBMb2dpbk9wdGlvbnMge1xyXG4gIC8qKlxyXG4gICAqIElzIGNhbGxlZCwgYWZ0ZXIgYSB0b2tlbiBoYXMgYmVlbiByZWNlaXZlZCBhbmRcclxuICAgKiBzdWNjZXNzZnVsbHkgdmFsaWRhdGVkLlxyXG4gICAqXHJcbiAgICogRGVwcmVjYXRlZDogIFVzZSBwcm9wZXJ0eSBgYGV2ZW50c2BgIG9uIE9BdXRoU2VydmljZSBpbnN0ZWFkLlxyXG4gICAqL1xyXG4gIG9uVG9rZW5SZWNlaXZlZD86IChyZWNlaXZlZFRva2VuczogUmVjZWl2ZWRUb2tlbnMpID0+IHZvaWQ7XHJcblxyXG4gIC8qKlxyXG4gICAqIEhvb2ssIHRvIHZhbGlkYXRlIHRoZSByZWNlaXZlZCB0b2tlbnMuXHJcbiAgICpcclxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcmBgIG9uIE9BdXRoU2VydmljZSBpbnN0ZWFkLlxyXG4gICAqL1xyXG4gIHZhbGlkYXRpb25IYW5kbGVyPzogKHJlY2VpdmVkVG9rZW5zOiBSZWNlaXZlZFRva2VucykgPT4gUHJvbWlzZTxhbnk+O1xyXG5cclxuICAvKipcclxuICAgKiBDYWxsZWQgd2hlbiB0cnlMb2dpbiBkZXRlY3RzIHRoYXQgdGhlIGF1dGggc2VydmVyXHJcbiAgICogaW5jbHVkZWQgYW4gZXJyb3IgbWVzc2FnZSBpbnRvIHRoZSBoYXNoIGZyYWdtZW50LlxyXG4gICAqXHJcbiAgICogRGVwcmVjYXRlZDogIFVzZSBwcm9wZXJ0eSBgYGV2ZW50c2BgIG9uIE9BdXRoU2VydmljZSBpbnN0ZWFkLlxyXG4gICAqL1xyXG4gIG9uTG9naW5FcnJvcj86IChwYXJhbXM6IG9iamVjdCkgPT4gdm9pZDtcclxuXHJcbiAgLyoqXHJcbiAgICogQSBjdXN0b20gaGFzaCBmcmFnbWVudCB0byBiZSB1c2VkIGluc3RlYWQgb2YgdGhlXHJcbiAgICogYWN0dWFsIG9uZS4gVGhpcyBpcyB1c2VkIGZvciBzaWxlbnQgcmVmcmVzaGVzLCB0b1xyXG4gICAqIHBhc3MgdGhlIGlmcmFtZXMgaGFzaCBmcmFnbWVudCB0byB0aGlzIG1ldGhvZC5cclxuICAgKi9cclxuICBjdXN0b21IYXNoRnJhZ21lbnQ/OiBzdHJpbmc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gZGlzYWJsZSB0aGUgb2F1dGgyIHN0YXRlXHJcbiAgICogY2hlY2sgd2hpY2ggaXMgYSBiZXN0IHByYWN0aWNlIHRvIGF2b2lkXHJcbiAgICogc2VjdXJpdHkgYXR0YWNrcy5cclxuICAgKiBBcyBPSURDIGRlZmluZXMgYSBub25jZSBjaGVjayB0aGF0IGluY2x1ZGVzXHJcbiAgICogdGhpcywgdGhpcyBjYW4gYmUgc2V0IHRvIHRydWUgd2hlbiBvbmx5IGRvaW5nXHJcbiAgICogT0lEQy5cclxuICAgKi9cclxuICBkaXNhYmxlT0F1dGgyU3RhdGVDaGVjaz86IGJvb2xlYW47XHJcblxyXG4gIC8qKlxyXG4gICAqIE5vcm1hbGx5LCB5b3Ugd2FudCB0byBjbGVhciB5b3VyIGhhc2ggZnJhZ21lbnQgYWZ0ZXJcclxuICAgKiB0aGUgbGliIHJlYWQgdGhlIHRva2VuKHMpIHNvIHRoYXQgdGhleSBhcmUgbm90IGRpc3BsYXllZFxyXG4gICAqIGFueW1vcmUgaW4gdGhlIHVybC4gSWYgbm90LCBzZXQgdGhpcyB0byB0cnVlLlxyXG4gICAqL1xyXG4gIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luPyA9IGZhbHNlO1xyXG59XHJcblxyXG4vKipcclxuICogRGVmaW5lcyB0aGUgbG9nZ2luZyBpbnRlcmZhY2UgdGhlIE9BdXRoU2VydmljZSB1c2VzXHJcbiAqIGludGVybmFsbHkuIElzIGNvbXBhdGlibGUgd2l0aCB0aGUgYGNvbnNvbGVgIG9iamVjdCxcclxuICogYnV0IHlvdSBjYW4gcHJvdmlkZSB5b3VyIG93biBpbXBsZW1lbnRhdGlvbiBhcyB3ZWxsXHJcbiAqIHRocm91Z2ggZGVwZW5kZW5jeSBpbmplY3Rpb24uXHJcbiAqL1xyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhMb2dnZXIge1xyXG4gIGFic3RyYWN0IGRlYnVnKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XHJcbiAgYWJzdHJhY3QgaW5mbyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xyXG4gIGFic3RyYWN0IGxvZyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xyXG4gIGFic3RyYWN0IHdhcm4obWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcclxuICBhYnN0cmFjdCBlcnJvcihtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xyXG59XHJcblxyXG4vKipcclxuICogRGVmaW5lcyBhIHNpbXBsZSBzdG9yYWdlIHRoYXQgY2FuIGJlIHVzZWQgZm9yXHJcbiAqIHN0b3JpbmcgdGhlIHRva2VucyBhdCBjbGllbnQgc2lkZS5cclxuICogSXMgY29tcGF0aWJsZSB0byBsb2NhbFN0b3JhZ2UgYW5kIHNlc3Npb25TdG9yYWdlLFxyXG4gKiBidXQgeW91IGNhbiBhbHNvIGNyZWF0ZSB5b3VyIG93biBpbXBsZW1lbnRhdGlvbnMuXHJcbiAqL1xyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhTdG9yYWdlIHtcclxuICBhYnN0cmFjdCBnZXRJdGVtKGtleTogc3RyaW5nKTogc3RyaW5nIHwgbnVsbDtcclxuICBhYnN0cmFjdCByZW1vdmVJdGVtKGtleTogc3RyaW5nKTogdm9pZDtcclxuICBhYnN0cmFjdCBzZXRJdGVtKGtleTogc3RyaW5nLCBkYXRhOiBzdHJpbmcpOiB2b2lkO1xyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyB0aGUgcmVjZWl2ZWQgdG9rZW5zLCB0aGUgcmVjZWl2ZWQgc3RhdGVcclxuICogYW5kIHRoZSBwYXJzZWQgY2xhaW1zIGZyb20gdGhlIGlkLXRva2VuLlxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIFJlY2VpdmVkVG9rZW5zIHtcclxuICBpZFRva2VuOiBzdHJpbmc7XHJcbiAgYWNjZXNzVG9rZW46IHN0cmluZztcclxuICBpZENsYWltcz86IG9iamVjdDtcclxuICBzdGF0ZT86IHN0cmluZztcclxufVxyXG5cclxuLyoqXHJcbiAqIFJlcHJlc2VudHMgdGhlIHBhcnNlZCBhbmQgdmFsaWRhdGVkIGlkX3Rva2VuLlxyXG4gKi9cclxuZXhwb3J0IGludGVyZmFjZSBQYXJzZWRJZFRva2VuIHtcclxuICBpZFRva2VuOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkNsYWltczogb2JqZWN0O1xyXG4gIGlkVG9rZW5IZWFkZXI6IG9iamVjdDtcclxuICBpZFRva2VuQ2xhaW1zSnNvbjogc3RyaW5nO1xyXG4gIGlkVG9rZW5IZWFkZXJKc29uOiBzdHJpbmc7XHJcbiAgaWRUb2tlbkV4cGlyZXNBdDogbnVtYmVyO1xyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgdG9rZW4gZW5kcG9pbnRcclxuICogaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtY29yZS0xXzAuaHRtbCNUb2tlbkVuZHBvaW50XHJcbiAqL1xyXG5leHBvcnQgaW50ZXJmYWNlIFRva2VuUmVzcG9uc2Uge1xyXG4gIGFjY2Vzc190b2tlbjogc3RyaW5nO1xyXG4gIGlkX3Rva2VuOiBzdHJpbmc7IFxyXG4gIHRva2VuX3R5cGU6IHN0cmluZztcclxuICBleHBpcmVzX2luOiBudW1iZXI7XHJcbiAgcmVmcmVzaF90b2tlbjogc3RyaW5nO1xyXG4gIHNjb3BlOiBzdHJpbmc7XHJcbiAgc3RhdGU/OiBzdHJpbmc7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBSZXByZXNlbnRzIHRoZSByZXNwb25zZSBmcm9tIHRoZSB1c2VyIGluZm8gZW5kcG9pbnRcclxuICogaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtY29yZS0xXzAuaHRtbCNVc2VySW5mb1xyXG4gKi9cclxuZXhwb3J0IGludGVyZmFjZSBVc2VySW5mbyB7XHJcbiAgc3ViOiBzdHJpbmc7XHJcbiAgW2tleTogc3RyaW5nXTogYW55O1xyXG59XHJcblxyXG4vKipcclxuICogUmVwcmVzZW50cyBhbiBPcGVuSUQgQ29ubmVjdCBkaXNjb3ZlcnkgZG9jdW1lbnRcclxuICovXHJcbmV4cG9ydCBpbnRlcmZhY2UgT2lkY0Rpc2NvdmVyeURvYyB7XHJcbiAgaXNzdWVyOiBzdHJpbmc7XHJcbiAgYXV0aG9yaXphdGlvbl9lbmRwb2ludDogc3RyaW5nO1xyXG4gIHRva2VuX2VuZHBvaW50OiBzdHJpbmc7XHJcbiAgdG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgdG9rZW5fZW5kcG9pbnRfYXV0aF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICB1c2VyaW5mb19lbmRwb2ludDogc3RyaW5nO1xyXG4gIGNoZWNrX3Nlc3Npb25faWZyYW1lOiBzdHJpbmc7XHJcbiAgZW5kX3Nlc3Npb25fZW5kcG9pbnQ6IHN0cmluZztcclxuICBqd2tzX3VyaTogc3RyaW5nO1xyXG4gIHJlZ2lzdHJhdGlvbl9lbmRwb2ludDogc3RyaW5nO1xyXG4gIHNjb3Blc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgYWNyX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIHJlc3BvbnNlX21vZGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgZ3JhbnRfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgdXNlcmluZm9fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgdXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgdXNlcmluZm9fZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgaWRfdG9rZW5fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgaWRfdG9rZW5fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgaWRfdG9rZW5fZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgcmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XHJcbiAgZGlzcGxheV92YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxuICBjbGFpbV90eXBlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIGNsYWltc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xyXG4gIGNsYWltc19wYXJhbWV0ZXJfc3VwcG9ydGVkOiBib29sZWFuO1xyXG4gIHNlcnZpY2VfZG9jdW1lbnRhdGlvbjogc3RyaW5nO1xyXG4gIHVpX2xvY2FsZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcclxufVxyXG4iXX0=