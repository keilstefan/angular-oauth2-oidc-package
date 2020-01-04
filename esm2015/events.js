/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
export class OAuthEvent {
    /**
     * @param {?} type
     */
    constructor(type) {
        this.type = type;
    }
}
if (false) {
    /** @type {?} */
    OAuthEvent.prototype.type;
}
export class OAuthSuccessEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
if (false) {
    /** @type {?} */
    OAuthSuccessEvent.prototype.info;
}
export class OAuthInfoEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
if (false) {
    /** @type {?} */
    OAuthInfoEvent.prototype.info;
}
export class OAuthErrorEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?} reason
     * @param {?=} params
     */
    constructor(type, reason, params = null) {
        super(type);
        this.reason = reason;
        this.params = params;
    }
}
if (false) {
    /** @type {?} */
    OAuthErrorEvent.prototype.reason;
    /** @type {?} */
    OAuthErrorEvent.prototype.params;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBd0JBLE1BQU0sT0FBZ0IsVUFBVTs7OztJQUM5QixZQUFxQixJQUFlO1FBQWYsU0FBSSxHQUFKLElBQUksQ0FBVztJQUFHLENBQUM7Q0FDekM7OztJQURhLDBCQUF3Qjs7QUFHdEMsTUFBTSxPQUFPLGlCQUFrQixTQUFRLFVBQVU7Ozs7O0lBQy9DLFlBQVksSUFBZSxFQUFXLE9BQVksSUFBSTtRQUNwRCxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUM7UUFEd0IsU0FBSSxHQUFKLElBQUksQ0FBWTtJQUV0RCxDQUFDO0NBQ0Y7OztJQUg4QixpQ0FBeUI7O0FBS3hELE1BQU0sT0FBTyxjQUFlLFNBQVEsVUFBVTs7Ozs7SUFDNUMsWUFBWSxJQUFlLEVBQVcsT0FBWSxJQUFJO1FBQ3BELEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUR3QixTQUFJLEdBQUosSUFBSSxDQUFZO0lBRXRELENBQUM7Q0FDRjs7O0lBSDhCLDhCQUF5Qjs7QUFLeEQsTUFBTSxPQUFPLGVBQWdCLFNBQVEsVUFBVTs7Ozs7O0lBQzdDLFlBQ0UsSUFBZSxFQUNOLE1BQWMsRUFDZCxTQUFpQixJQUFJO1FBRTlCLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUhILFdBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxXQUFNLEdBQU4sTUFBTSxDQUFlO0lBR2hDLENBQUM7Q0FDRjs7O0lBTEcsaUNBQXVCOztJQUN2QixpQ0FBOEIiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgdHlwZSBFdmVudFR5cGUgPVxyXG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnXHJcbiAgfCAncmVjZWl2ZWRfZmlyc3RfdG9rZW4nXHJcbiAgfCAnandrc19sb2FkX2Vycm9yJ1xyXG4gIHwgJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnXHJcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InXHJcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InXHJcbiAgfCAndXNlcl9wcm9maWxlX2xvYWRlZCdcclxuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcidcclxuICB8ICd0b2tlbl9yZWNlaXZlZCdcclxuICB8ICd0b2tlbl9lcnJvcidcclxuICB8ICdjb2RlX2Vycm9yJ1xyXG4gIHwgJ3Rva2VuX3JlZnJlc2hlZCdcclxuICB8ICd0b2tlbl9yZWZyZXNoX2Vycm9yJ1xyXG4gIHwgJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xyXG4gIHwgJ3NpbGVudGx5X3JlZnJlc2hlZCdcclxuICB8ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0J1xyXG4gIHwgJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InXHJcbiAgfCAndG9rZW5fZXhwaXJlcydcclxuICB8ICdzZXNzaW9uX2NoYW5nZWQnXHJcbiAgfCAnc2Vzc2lvbl9lcnJvcidcclxuICB8ICdzZXNzaW9uX3Rlcm1pbmF0ZWQnXHJcbiAgfCAnbG9nb3V0JztcclxuXHJcbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3RvcihyZWFkb25seSB0eXBlOiBFdmVudFR5cGUpIHt9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBPQXV0aFN1Y2Nlc3NFdmVudCBleHRlbmRzIE9BdXRoRXZlbnQge1xyXG4gIGNvbnN0cnVjdG9yKHR5cGU6IEV2ZW50VHlwZSwgcmVhZG9ubHkgaW5mbzogYW55ID0gbnVsbCkge1xyXG4gICAgc3VwZXIodHlwZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgT0F1dGhJbmZvRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcclxuICBjb25zdHJ1Y3Rvcih0eXBlOiBFdmVudFR5cGUsIHJlYWRvbmx5IGluZm86IGFueSA9IG51bGwpIHtcclxuICAgIHN1cGVyKHR5cGUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE9BdXRoRXJyb3JFdmVudCBleHRlbmRzIE9BdXRoRXZlbnQge1xyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgdHlwZTogRXZlbnRUeXBlLFxyXG4gICAgcmVhZG9ubHkgcmVhc29uOiBvYmplY3QsXHJcbiAgICByZWFkb25seSBwYXJhbXM6IG9iamVjdCA9IG51bGxcclxuICApIHtcclxuICAgIHN1cGVyKHR5cGUpO1xyXG4gIH1cclxufVxyXG4iXX0=