/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
export class UrlHelperService {
    /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    getHashFragmentParams(customHashFragment) {
        /** @type {?} */
        let hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        /** @type {?} */
        const questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    }
    /**
     * @param {?} queryString
     * @return {?}
     */
    parseQueryString(queryString) {
        /** @type {?} */
        const data = {};
        /** @type {?} */
        let pairs;
        /** @type {?} */
        let pair;
        /** @type {?} */
        let separatorIndex;
        /** @type {?} */
        let escapedKey;
        /** @type {?} */
        let escapedValue;
        /** @type {?} */
        let key;
        /** @type {?} */
        let value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (let i = 0; i < pairs.length; i++) {
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
    }
}
UrlHelperService.decorators = [
    { type: Injectable }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUczQyxNQUFNLE9BQU8sZ0JBQWdCOzs7OztJQUNwQixxQkFBcUIsQ0FBQyxrQkFBMkI7O1lBQ2xELElBQUksR0FBRyxrQkFBa0IsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUk7UUFFckQsSUFBSSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWhDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDWDs7Y0FFSyxvQkFBb0IsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUU5QyxJQUFJLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxFQUFFO1lBQzdCLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxDQUFDO1NBQzlDO2FBQU07WUFDTCxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN2QjtRQUVELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3JDLENBQUM7Ozs7O0lBRU0sZ0JBQWdCLENBQUMsV0FBbUI7O2NBQ25DLElBQUksR0FBRyxFQUFFOztZQUViLEtBQUs7O1lBQ0wsSUFBSTs7WUFDSixjQUFjOztZQUNkLFVBQVU7O1lBQ1YsWUFBWTs7WUFDWixHQUFHOztZQUNILEtBQUs7UUFFUCxJQUFJLFdBQVcsS0FBSyxJQUFJLEVBQUU7WUFDeEIsT0FBTyxJQUFJLENBQUM7U0FDYjtRQUVELEtBQUssR0FBRyxXQUFXLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRS9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFO1lBQ3JDLElBQUksR0FBRyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDaEIsY0FBYyxHQUFHLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUM7WUFFbkMsSUFBSSxjQUFjLEtBQUssQ0FBQyxDQUFDLEVBQUU7Z0JBQ3pCLFVBQVUsR0FBRyxJQUFJLENBQUM7Z0JBQ2xCLFlBQVksR0FBRyxJQUFJLENBQUM7YUFDckI7aUJBQU07Z0JBQ0wsVUFBVSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLGNBQWMsQ0FBQyxDQUFDO2dCQUM1QyxZQUFZLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxjQUFjLEdBQUcsQ0FBQyxDQUFDLENBQUM7YUFDaEQ7WUFFRCxHQUFHLEdBQUcsa0JBQWtCLENBQUMsVUFBVSxDQUFDLENBQUM7WUFDckMsS0FBSyxHQUFHLGtCQUFrQixDQUFDLFlBQVksQ0FBQyxDQUFDO1lBRXpDLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEtBQUssR0FBRyxFQUFFO2dCQUFFLEdBQUcsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO2FBQUU7WUFFdEQsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEtBQUssQ0FBQztTQUNuQjtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQzs7O1lBNURGLFVBQVUiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBVcmxIZWxwZXJTZXJ2aWNlIHtcclxuICBwdWJsaWMgZ2V0SGFzaEZyYWdtZW50UGFyYW1zKGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBsZXQgaGFzaCA9IGN1c3RvbUhhc2hGcmFnbWVudCB8fCB3aW5kb3cubG9jYXRpb24uaGFzaDtcclxuXHJcbiAgICBoYXNoID0gZGVjb2RlVVJJQ29tcG9uZW50KGhhc2gpO1xyXG5cclxuICAgIGlmIChoYXNoLmluZGV4T2YoJyMnKSAhPT0gMCkge1xyXG4gICAgICByZXR1cm4ge307XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcXVlc3Rpb25NYXJrUG9zaXRpb24gPSBoYXNoLmluZGV4T2YoJz8nKTtcclxuXHJcbiAgICBpZiAocXVlc3Rpb25NYXJrUG9zaXRpb24gPiAtMSkge1xyXG4gICAgICBoYXNoID0gaGFzaC5zdWJzdHIocXVlc3Rpb25NYXJrUG9zaXRpb24gKyAxKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGhhc2ggPSBoYXNoLnN1YnN0cigxKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKGhhc2gpO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBjb25zdCBkYXRhID0ge307XHJcbiAgICBsZXRcclxuICAgICAgcGFpcnMsXHJcbiAgICAgIHBhaXIsXHJcbiAgICAgIHNlcGFyYXRvckluZGV4LFxyXG4gICAgICBlc2NhcGVkS2V5LFxyXG4gICAgICBlc2NhcGVkVmFsdWUsXHJcbiAgICAgIGtleSxcclxuICAgICAgdmFsdWU7XHJcblxyXG4gICAgaWYgKHF1ZXJ5U3RyaW5nID09PSBudWxsKSB7XHJcbiAgICAgIHJldHVybiBkYXRhO1xyXG4gICAgfVxyXG5cclxuICAgIHBhaXJzID0gcXVlcnlTdHJpbmcuc3BsaXQoJyYnKTtcclxuXHJcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHBhaXJzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgIHBhaXIgPSBwYWlyc1tpXTtcclxuICAgICAgc2VwYXJhdG9ySW5kZXggPSBwYWlyLmluZGV4T2YoJz0nKTtcclxuXHJcbiAgICAgIGlmIChzZXBhcmF0b3JJbmRleCA9PT0gLTEpIHtcclxuICAgICAgICBlc2NhcGVkS2V5ID0gcGFpcjtcclxuICAgICAgICBlc2NhcGVkVmFsdWUgPSBudWxsO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyLnN1YnN0cigwLCBzZXBhcmF0b3JJbmRleCk7XHJcbiAgICAgICAgZXNjYXBlZFZhbHVlID0gcGFpci5zdWJzdHIoc2VwYXJhdG9ySW5kZXggKyAxKTtcclxuICAgICAgfVxyXG5cclxuICAgICAga2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRLZXkpO1xyXG4gICAgICB2YWx1ZSA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGVkVmFsdWUpO1xyXG5cclxuICAgICAgaWYgKGtleS5zdWJzdHIoMCwgMSkgPT09ICcvJykgeyBrZXkgPSBrZXkuc3Vic3RyKDEpOyB9XHJcblxyXG4gICAgICBkYXRhW2tleV0gPSB2YWx1ZTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gZGF0YTtcclxuICB9XHJcbn1cclxuIl19