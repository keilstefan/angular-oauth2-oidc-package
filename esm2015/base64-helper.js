/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
// see: https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
/**
 * @param {?} str
 * @return {?}
 */
export function b64DecodeUnicode(str) {
    /** @type {?} */
    const base64 = str.replace(/\-/g, '+').replace(/\_/g, '/');
    return decodeURIComponent(atob(base64)
        .split('')
        .map((/**
     * @param {?} c
     * @return {?}
     */
    function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }))
        .join(''));
}
/**
 * @param {?} str
 * @return {?}
 */
export function base64UrlEncode(str) {
    /** @type {?} */
    const base64 = btoa(str);
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYmFzZTY0LWhlbHBlci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJiYXNlNjQtaGVscGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUNBLE1BQU0sVUFBVSxnQkFBZ0IsQ0FBQyxHQUFHOztVQUM1QixNQUFNLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUM7SUFFMUQsT0FBTyxrQkFBa0IsQ0FDdkIsSUFBSSxDQUFDLE1BQU0sQ0FBQztTQUNULEtBQUssQ0FBQyxFQUFFLENBQUM7U0FDVCxHQUFHOzs7O0lBQUMsVUFBUyxDQUFDO1FBQ2IsT0FBTyxHQUFHLEdBQUcsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvRCxDQUFDLEVBQUM7U0FDRCxJQUFJLENBQUMsRUFBRSxDQUFDLENBQ1osQ0FBQztBQUNKLENBQUM7Ozs7O0FBRUQsTUFBTSxVQUFVLGVBQWUsQ0FBQyxHQUFHOztVQUMzQixNQUFNLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQztJQUN4QixPQUFPLE1BQU07U0FDVixPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQztTQUNuQixPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQztTQUNuQixPQUFPLENBQUMsSUFBSSxFQUFFLEVBQUUsQ0FBQyxDQUFDO0FBQ3ZCLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBzZWU6IGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9XaW5kb3dCYXNlNjQvQmFzZTY0X2VuY29kaW5nX2FuZF9kZWNvZGluZyNUaGVfLjIyVW5pY29kZV9Qcm9ibGVtLjIyXHJcbmV4cG9ydCBmdW5jdGlvbiBiNjREZWNvZGVVbmljb2RlKHN0cikge1xyXG4gIGNvbnN0IGJhc2U2NCA9IHN0ci5yZXBsYWNlKC9cXC0vZywgJysnKS5yZXBsYWNlKC9cXF8vZywgJy8nKTtcclxuXHJcbiAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChcclxuICAgIGF0b2IoYmFzZTY0KVxyXG4gICAgICAuc3BsaXQoJycpXHJcbiAgICAgIC5tYXAoZnVuY3Rpb24oYykge1xyXG4gICAgICAgIHJldHVybiAnJScgKyAoJzAwJyArIGMuY2hhckNvZGVBdCgwKS50b1N0cmluZygxNikpLnNsaWNlKC0yKTtcclxuICAgICAgfSlcclxuICAgICAgLmpvaW4oJycpXHJcbiAgKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShzdHIpOiBzdHJpbmcge1xyXG4gIGNvbnN0IGJhc2U2NCA9IGJ0b2Eoc3RyKTtcclxuICByZXR1cm4gYmFzZTY0XHJcbiAgICAucmVwbGFjZSgvXFwrL2csICctJylcclxuICAgIC5yZXBsYWNlKC9cXC8vZywgJ18nKVxyXG4gICAgLnJlcGxhY2UoLz0vZywgJycpO1xyXG59Il19