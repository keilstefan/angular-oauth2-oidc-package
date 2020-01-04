/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthModuleConfig = /** @class */ (function () {
    function OAuthModuleConfig() {
    }
    return OAuthModuleConfig;
}());
/**
 * @abstract
 */
export { OAuthModuleConfig };
if (false) {
    /** @type {?} */
    OAuthModuleConfig.prototype.resourceServer;
}
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthResourceServerConfig = /** @class */ (function () {
    function OAuthResourceServerConfig() {
    }
    return OAuthResourceServerConfig;
}());
/**
 * @abstract
 */
export { OAuthResourceServerConfig };
if (false) {
    /**
     * Urls for which calls should be intercepted.
     * If there is an ResourceServerErrorHandler registered, it is used for them.
     * If sendAccessToken is set to true, the access_token is send to them too.
     * @type {?}
     */
    OAuthResourceServerConfig.prototype.allowedUrls;
    /** @type {?} */
    OAuthResourceServerConfig.prototype.sendAccessToken;
    /** @type {?} */
    OAuthResourceServerConfig.prototype.customUrlValidation;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtbW9kdWxlLmNvbmZpZy5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1tb2R1bGUuY29uZmlnLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTs7OztJQUFBO0lBRUEsQ0FBQztJQUFELHdCQUFDO0FBQUQsQ0FBQyxBQUZELElBRUM7Ozs7Ozs7SUFEQywyQ0FBMEM7Ozs7O0FBRzVDOzs7O0lBQUE7SUFTQSxDQUFDO0lBQUQsZ0NBQUM7QUFBRCxDQUFDLEFBVEQsSUFTQzs7Ozs7Ozs7Ozs7O0lBSEMsZ0RBQTRCOztJQUM1QixvREFBeUI7O0lBQ3pCLHdEQUErQyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aE1vZHVsZUNvbmZpZyB7XHJcbiAgcmVzb3VyY2VTZXJ2ZXI6IE9BdXRoUmVzb3VyY2VTZXJ2ZXJDb25maWc7XHJcbn1cclxuXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aFJlc291cmNlU2VydmVyQ29uZmlnIHtcclxuICAvKipcclxuICAgKiBVcmxzIGZvciB3aGljaCBjYWxscyBzaG91bGQgYmUgaW50ZXJjZXB0ZWQuXHJcbiAgICogSWYgdGhlcmUgaXMgYW4gUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIgcmVnaXN0ZXJlZCwgaXQgaXMgdXNlZCBmb3IgdGhlbS5cclxuICAgKiBJZiBzZW5kQWNjZXNzVG9rZW4gaXMgc2V0IHRvIHRydWUsIHRoZSBhY2Nlc3NfdG9rZW4gaXMgc2VuZCB0byB0aGVtIHRvby5cclxuICAgKi9cclxuICBhbGxvd2VkVXJscz86IEFycmF5PHN0cmluZz47XHJcbiAgc2VuZEFjY2Vzc1Rva2VuOiBib29sZWFuO1xyXG4gIGN1c3RvbVVybFZhbGlkYXRpb24/OiAodXJsOiBzdHJpbmcpID0+IGJvb2xlYW47XHJcbn1cclxuIl19