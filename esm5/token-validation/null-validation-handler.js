/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
var /**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
NullValidationHandler = /** @class */ (function () {
    function NullValidationHandler() {
    }
    /**
     * @param {?} validationParams
     * @return {?}
     */
    NullValidationHandler.prototype.validateSignature = /**
     * @param {?} validationParams
     * @return {?}
     */
    function (validationParams) {
        return Promise.resolve(null);
    };
    /**
     * @param {?} validationParams
     * @return {?}
     */
    NullValidationHandler.prototype.validateAtHash = /**
     * @param {?} validationParams
     * @return {?}
     */
    function (validationParams) {
        return Promise.resolve(true);
    };
    return NullValidationHandler;
}());
/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
export { NullValidationHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibnVsbC12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQU1BOzs7OztJQUFBO0lBT0EsQ0FBQzs7Ozs7SUFOQyxpREFBaUI7Ozs7SUFBakIsVUFBa0IsZ0JBQWtDO1FBQ2xELE9BQU8sT0FBTyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUMvQixDQUFDOzs7OztJQUNELDhDQUFjOzs7O0lBQWQsVUFBZSxnQkFBa0M7UUFDL0MsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQy9CLENBQUM7SUFDSCw0QkFBQztBQUFELENBQUMsQUFQRCxJQU9DIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgVmFsaWRhdGlvbkhhbmRsZXIsIFZhbGlkYXRpb25QYXJhbXMgfSBmcm9tICcuL3ZhbGlkYXRpb24taGFuZGxlcic7XHJcblxyXG4vKipcclxuICogQSB2YWxpZGF0aW9uIGhhbmRsZXIgdGhhdCBpc24ndCB2YWxpZGF0aW5nIG5vdGhpbmcuXHJcbiAqIENhbiBiZSB1c2VkIHRvIHNraXAgdmFsaWRhdGlvbiAoYXQgeW91ciBvd24gcmlzaykuXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgTnVsbFZhbGlkYXRpb25IYW5kbGVyIGltcGxlbWVudHMgVmFsaWRhdGlvbkhhbmRsZXIge1xyXG4gIHZhbGlkYXRlU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcclxuICB9XHJcbiAgdmFsaWRhdGVBdEhhc2godmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcclxuICB9XHJcbn1cclxuIl19