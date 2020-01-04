/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { throwError } from 'rxjs';
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthResourceServerErrorHandler = /** @class */ (function () {
    function OAuthResourceServerErrorHandler() {
    }
    return OAuthResourceServerErrorHandler;
}());
/**
 * @abstract
 */
export { OAuthResourceServerErrorHandler };
if (false) {
    /**
     * @abstract
     * @param {?} err
     * @return {?}
     */
    OAuthResourceServerErrorHandler.prototype.handleError = function (err) { };
}
var OAuthNoopResourceServerErrorHandler = /** @class */ (function () {
    function OAuthNoopResourceServerErrorHandler() {
    }
    /**
     * @param {?} err
     * @return {?}
     */
    OAuthNoopResourceServerErrorHandler.prototype.handleError = /**
     * @param {?} err
     * @return {?}
     */
    function (err) {
        return throwError(err);
    };
    return OAuthNoopResourceServerErrorHandler;
}());
export { OAuthNoopResourceServerErrorHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFDQSxPQUFPLEVBQWMsVUFBVSxFQUFFLE1BQU0sTUFBTSxDQUFDOzs7O0FBRTlDOzs7O0lBQUE7SUFFQSxDQUFDO0lBQUQsc0NBQUM7QUFBRCxDQUFDLEFBRkQsSUFFQzs7Ozs7Ozs7Ozs7SUFEQywyRUFBOEQ7O0FBR2hFO0lBQUE7SUFLQSxDQUFDOzs7OztJQUhDLHlEQUFXOzs7O0lBQVgsVUFBWSxHQUFzQjtRQUNoQyxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN6QixDQUFDO0lBQ0gsMENBQUM7QUFBRCxDQUFDLEFBTEQsSUFLQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEh0dHBSZXNwb25zZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcclxuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgdGhyb3dFcnJvciB9IGZyb20gJ3J4anMnO1xyXG5cclxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIge1xyXG4gIGFic3RyYWN0IGhhbmRsZUVycm9yKGVycjogSHR0cFJlc3BvbnNlPGFueT4pOiBPYnNlcnZhYmxlPGFueT47XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxyXG4gIGltcGxlbWVudHMgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB7XHJcbiAgaGFuZGxlRXJyb3IoZXJyOiBIdHRwUmVzcG9uc2U8YW55Pik6IE9ic2VydmFibGU8YW55PiB7XHJcbiAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xyXG4gIH1cclxufVxyXG4iXX0=