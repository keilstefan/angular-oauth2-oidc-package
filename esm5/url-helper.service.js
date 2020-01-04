/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
var UrlHelperService = /** @class */ (function () {
    function UrlHelperService() {
    }
    /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    UrlHelperService.prototype.getHashFragmentParams = /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    function (customHashFragment) {
        /** @type {?} */
        var hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        /** @type {?} */
        var questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    };
    /**
     * @param {?} queryString
     * @return {?}
     */
    UrlHelperService.prototype.parseQueryString = /**
     * @param {?} queryString
     * @return {?}
     */
    function (queryString) {
        /** @type {?} */
        var data = {};
        /** @type {?} */
        var pairs;
        /** @type {?} */
        var pair;
        /** @type {?} */
        var separatorIndex;
        /** @type {?} */
        var escapedKey;
        /** @type {?} */
        var escapedValue;
        /** @type {?} */
        var key;
        /** @type {?} */
        var value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    };
    UrlHelperService.decorators = [
        { type: Injectable }
    ];
    return UrlHelperService;
}());
export { UrlHelperService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUUzQztJQUFBO0lBNkRBLENBQUM7Ozs7O0lBM0RRLGdEQUFxQjs7OztJQUE1QixVQUE2QixrQkFBMkI7O1lBQ2xELElBQUksR0FBRyxrQkFBa0IsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUk7UUFFckQsSUFBSSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWhDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDWDs7WUFFSyxvQkFBb0IsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUU5QyxJQUFJLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxFQUFFO1lBQzdCLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxDQUFDO1NBQzlDO2FBQU07WUFDTCxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN2QjtRQUVELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3JDLENBQUM7Ozs7O0lBRU0sMkNBQWdCOzs7O0lBQXZCLFVBQXdCLFdBQW1COztZQUNuQyxJQUFJLEdBQUcsRUFBRTs7WUFFYixLQUFLOztZQUNMLElBQUk7O1lBQ0osY0FBYzs7WUFDZCxVQUFVOztZQUNWLFlBQVk7O1lBQ1osR0FBRzs7WUFDSCxLQUFLO1FBRVAsSUFBSSxXQUFXLEtBQUssSUFBSSxFQUFFO1lBQ3hCLE9BQU8sSUFBSSxDQUFDO1NBQ2I7UUFFRCxLQUFLLEdBQUcsV0FBVyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUUvQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsS0FBSyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRTtZQUNyQyxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLGNBQWMsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBRW5DLElBQUksY0FBYyxLQUFLLENBQUMsQ0FBQyxFQUFFO2dCQUN6QixVQUFVLEdBQUcsSUFBSSxDQUFDO2dCQUNsQixZQUFZLEdBQUcsSUFBSSxDQUFDO2FBQ3JCO2lCQUFNO2dCQUNMLFVBQVUsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQztnQkFDNUMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsY0FBYyxHQUFHLENBQUMsQ0FBQyxDQUFDO2FBQ2hEO1lBRUQsR0FBRyxHQUFHLGtCQUFrQixDQUFDLFVBQVUsQ0FBQyxDQUFDO1lBQ3JDLEtBQUssR0FBRyxrQkFBa0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztZQUV6QyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLLEdBQUcsRUFBRTtnQkFBRSxHQUFHLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUFFO1lBRXRELElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxLQUFLLENBQUM7U0FDbkI7UUFFRCxPQUFPLElBQUksQ0FBQztJQUNkLENBQUM7O2dCQTVERixVQUFVOztJQTZEWCx1QkFBQztDQUFBLEFBN0RELElBNkRDO1NBNURZLGdCQUFnQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIFVybEhlbHBlclNlcnZpY2Uge1xyXG4gIHB1YmxpYyBnZXRIYXNoRnJhZ21lbnRQYXJhbXMoY3VzdG9tSGFzaEZyYWdtZW50Pzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGxldCBoYXNoID0gY3VzdG9tSGFzaEZyYWdtZW50IHx8IHdpbmRvdy5sb2NhdGlvbi5oYXNoO1xyXG5cclxuICAgIGhhc2ggPSBkZWNvZGVVUklDb21wb25lbnQoaGFzaCk7XHJcblxyXG4gICAgaWYgKGhhc2guaW5kZXhPZignIycpICE9PSAwKSB7XHJcbiAgICAgIHJldHVybiB7fTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBxdWVzdGlvbk1hcmtQb3NpdGlvbiA9IGhhc2guaW5kZXhPZignPycpO1xyXG5cclxuICAgIGlmIChxdWVzdGlvbk1hcmtQb3NpdGlvbiA+IC0xKSB7XHJcbiAgICAgIGhhc2ggPSBoYXNoLnN1YnN0cihxdWVzdGlvbk1hcmtQb3NpdGlvbiArIDEpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgaGFzaCA9IGhhc2guc3Vic3RyKDEpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0aGlzLnBhcnNlUXVlcnlTdHJpbmcoaGFzaCk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGNvbnN0IGRhdGEgPSB7fTtcclxuICAgIGxldFxyXG4gICAgICBwYWlycyxcclxuICAgICAgcGFpcixcclxuICAgICAgc2VwYXJhdG9ySW5kZXgsXHJcbiAgICAgIGVzY2FwZWRLZXksXHJcbiAgICAgIGVzY2FwZWRWYWx1ZSxcclxuICAgICAga2V5LFxyXG4gICAgICB2YWx1ZTtcclxuXHJcbiAgICBpZiAocXVlcnlTdHJpbmcgPT09IG51bGwpIHtcclxuICAgICAgcmV0dXJuIGRhdGE7XHJcbiAgICB9XHJcblxyXG4gICAgcGFpcnMgPSBxdWVyeVN0cmluZy5zcGxpdCgnJicpO1xyXG5cclxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcGFpcnMubGVuZ3RoOyBpKyspIHtcclxuICAgICAgcGFpciA9IHBhaXJzW2ldO1xyXG4gICAgICBzZXBhcmF0b3JJbmRleCA9IHBhaXIuaW5kZXhPZignPScpO1xyXG5cclxuICAgICAgaWYgKHNlcGFyYXRvckluZGV4ID09PSAtMSkge1xyXG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyO1xyXG4gICAgICAgIGVzY2FwZWRWYWx1ZSA9IG51bGw7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgZXNjYXBlZEtleSA9IHBhaXIuc3Vic3RyKDAsIHNlcGFyYXRvckluZGV4KTtcclxuICAgICAgICBlc2NhcGVkVmFsdWUgPSBwYWlyLnN1YnN0cihzZXBhcmF0b3JJbmRleCArIDEpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBrZXkgPSBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlZEtleSk7XHJcbiAgICAgIHZhbHVlID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRWYWx1ZSk7XHJcblxyXG4gICAgICBpZiAoa2V5LnN1YnN0cigwLCAxKSA9PT0gJy8nKSB7IGtleSA9IGtleS5zdWJzdHIoMSk7IH1cclxuXHJcbiAgICAgIGRhdGFba2V5XSA9IHZhbHVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBkYXRhO1xyXG4gIH1cclxufVxyXG4iXX0=