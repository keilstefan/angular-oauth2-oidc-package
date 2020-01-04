/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthEvent = /** @class */ (function () {
    function OAuthEvent(type) {
        this.type = type;
    }
    return OAuthEvent;
}());
/**
 * @abstract
 */
export { OAuthEvent };
if (false) {
    /** @type {?} */
    OAuthEvent.prototype.type;
}
var OAuthSuccessEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthSuccessEvent, _super);
    function OAuthSuccessEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthSuccessEvent;
}(OAuthEvent));
export { OAuthSuccessEvent };
if (false) {
    /** @type {?} */
    OAuthSuccessEvent.prototype.info;
}
var OAuthInfoEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthInfoEvent, _super);
    function OAuthInfoEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthInfoEvent;
}(OAuthEvent));
export { OAuthInfoEvent };
if (false) {
    /** @type {?} */
    OAuthInfoEvent.prototype.info;
}
var OAuthErrorEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthErrorEvent, _super);
    function OAuthErrorEvent(type, reason, params) {
        if (params === void 0) { params = null; }
        var _this = _super.call(this, type) || this;
        _this.reason = reason;
        _this.params = params;
        return _this;
    }
    return OAuthErrorEvent;
}(OAuthEvent));
export { OAuthErrorEvent };
if (false) {
    /** @type {?} */
    OAuthErrorEvent.prototype.reason;
    /** @type {?} */
    OAuthErrorEvent.prototype.params;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQXdCQTs7OztJQUNFLG9CQUFxQixJQUFlO1FBQWYsU0FBSSxHQUFKLElBQUksQ0FBVztJQUFHLENBQUM7SUFDMUMsaUJBQUM7QUFBRCxDQUFDLEFBRkQsSUFFQzs7Ozs7OztJQURhLDBCQUF3Qjs7QUFHdEM7SUFBdUMsNkNBQVU7SUFDL0MsMkJBQVksSUFBZSxFQUFXLElBQWdCO1FBQWhCLHFCQUFBLEVBQUEsV0FBZ0I7UUFBdEQsWUFDRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUZxQyxVQUFJLEdBQUosSUFBSSxDQUFZOztJQUV0RCxDQUFDO0lBQ0gsd0JBQUM7QUFBRCxDQUFDLEFBSkQsQ0FBdUMsVUFBVSxHQUloRDs7OztJQUg4QixpQ0FBeUI7O0FBS3hEO0lBQW9DLDBDQUFVO0lBQzVDLHdCQUFZLElBQWUsRUFBVyxJQUFnQjtRQUFoQixxQkFBQSxFQUFBLFdBQWdCO1FBQXRELFlBQ0Usa0JBQU0sSUFBSSxDQUFDLFNBQ1o7UUFGcUMsVUFBSSxHQUFKLElBQUksQ0FBWTs7SUFFdEQsQ0FBQztJQUNILHFCQUFDO0FBQUQsQ0FBQyxBQUpELENBQW9DLFVBQVUsR0FJN0M7Ozs7SUFIOEIsOEJBQXlCOztBQUt4RDtJQUFxQywyQ0FBVTtJQUM3Qyx5QkFDRSxJQUFlLEVBQ04sTUFBYyxFQUNkLE1BQXFCO1FBQXJCLHVCQUFBLEVBQUEsYUFBcUI7UUFIaEMsWUFLRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUpVLFlBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxZQUFNLEdBQU4sTUFBTSxDQUFlOztJQUdoQyxDQUFDO0lBQ0gsc0JBQUM7QUFBRCxDQUFDLEFBUkQsQ0FBcUMsVUFBVSxHQVE5Qzs7OztJQUxHLGlDQUF1Qjs7SUFDdkIsaUNBQThCIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IHR5cGUgRXZlbnRUeXBlID1cclxuICB8ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJ1xyXG4gIHwgJ3JlY2VpdmVkX2ZpcnN0X3Rva2VuJ1xyXG4gIHwgJ2p3a3NfbG9hZF9lcnJvcidcclxuICB8ICdpbnZhbGlkX25vbmNlX2luX3N0YXRlJ1xyXG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJ1xyXG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJ1xyXG4gIHwgJ3VzZXJfcHJvZmlsZV9sb2FkZWQnXHJcbiAgfCAndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InXHJcbiAgfCAndG9rZW5fcmVjZWl2ZWQnXHJcbiAgfCAndG9rZW5fZXJyb3InXHJcbiAgfCAnY29kZV9lcnJvcidcclxuICB8ICd0b2tlbl9yZWZyZXNoZWQnXHJcbiAgfCAndG9rZW5fcmVmcmVzaF9lcnJvcidcclxuICB8ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcclxuICB8ICdzaWxlbnRseV9yZWZyZXNoZWQnXHJcbiAgfCAnc2lsZW50X3JlZnJlc2hfdGltZW91dCdcclxuICB8ICd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJ1xyXG4gIHwgJ3Rva2VuX2V4cGlyZXMnXHJcbiAgfCAnc2Vzc2lvbl9jaGFuZ2VkJ1xyXG4gIHwgJ3Nlc3Npb25fZXJyb3InXHJcbiAgfCAnc2Vzc2lvbl90ZXJtaW5hdGVkJ1xyXG4gIHwgJ2xvZ291dCc7XHJcblxyXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhFdmVudCB7XHJcbiAgY29uc3RydWN0b3IocmVhZG9ubHkgdHlwZTogRXZlbnRUeXBlKSB7fVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgT0F1dGhTdWNjZXNzRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3Rvcih0eXBlOiBFdmVudFR5cGUsIHJlYWRvbmx5IGluZm86IGFueSA9IG51bGwpIHtcclxuICAgIHN1cGVyKHR5cGUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE9BdXRoSW5mb0V2ZW50IGV4dGVuZHMgT0F1dGhFdmVudCB7XHJcbiAgY29uc3RydWN0b3IodHlwZTogRXZlbnRUeXBlLCByZWFkb25seSBpbmZvOiBhbnkgPSBudWxsKSB7XHJcbiAgICBzdXBlcih0eXBlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBPQXV0aEVycm9yRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3RvcihcclxuICAgIHR5cGU6IEV2ZW50VHlwZSxcclxuICAgIHJlYWRvbmx5IHJlYXNvbjogb2JqZWN0LFxyXG4gICAgcmVhZG9ubHkgcGFyYW1zOiBvYmplY3QgPSBudWxsXHJcbiAgKSB7XHJcbiAgICBzdXBlcih0eXBlKTtcclxuICB9XHJcbn1cclxuIl19