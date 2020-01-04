/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
import { Injectable, NgZone, Optional } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Subject, of, race, from } from 'rxjs';
import { filter, delay, first, tap, map, switchMap } from 'rxjs/operators';
import { ValidationHandler } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthInfoEvent, OAuthErrorEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { CryptoHandler } from './token-validation/crypto-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
var OAuthService = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthService, _super);
    function OAuthService(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto) {
        var _this = _super.call(this) || this;
        _this.ngZone = ngZone;
        _this.http = http;
        _this.config = config;
        _this.urlHelper = urlHelper;
        _this.logger = logger;
        _this.crypto = crypto;
        /**
         * \@internal
         * Deprecated:  use property events instead
         */
        _this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        _this.state = '';
        _this.eventsSubject = new Subject();
        _this.discoveryDocumentLoadedSubject = new Subject();
        _this.grantTypesSupported = [];
        _this.inImplicitFlow = false;
        _this.debug('angular-oauth2-oidc v8-beta');
        _this.discoveryDocumentLoaded$ = _this.discoveryDocumentLoadedSubject.asObservable();
        _this.events = _this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            _this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            _this.configure(config);
        }
        try {
            if (storage) {
                _this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                _this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).'
                + 'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        _this.setupRefreshTimer();
        return _this;
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    /**
     * Use this method to configure the service
     * @param {?} config the configuration
     * @return {?}
     */
    OAuthService.prototype.configure = /**
     * Use this method to configure the service
     * @param {?} config the configuration
     * @return {?}
     */
    function (config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign((/** @type {?} */ ({})), new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.configChanged = /**
     * @protected
     * @return {?}
     */
    function () {
        this.setupRefreshTimer();
    };
    /**
     * @return {?}
     */
    OAuthService.prototype.restartSessionChecksIfStillLoggedIn = /**
     * @return {?}
     */
    function () {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.restartRefreshTimerIfStillLoggedIn = /**
     * @protected
     * @return {?}
     */
    function () {
        this.setupExpirationTimers();
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupSessionCheck = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e.type === 'token_received'; }))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            _this.initSessionCheck();
        }));
    };
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param {?=} params Additional parameter to pass
     * @param {?=} listenTo Setup automatic refresh of a specific token type
     * @param {?=} noPrompt
     * @return {?}
     */
    OAuthService.prototype.setupAutomaticSilentRefresh = /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param {?=} params Additional parameter to pass
     * @param {?=} listenTo Setup automatic refresh of a specific token type
     * @param {?=} noPrompt
     * @return {?}
     */
    function (params, listenTo, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        /** @type {?} */
        var shouldRunSilentRefresh = true;
        this.events.pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        })), filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e.type === 'token_expires'; }))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            /** @type {?} */
            var event = (/** @type {?} */ (e));
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) && shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                _this.refreshInternal(params, noPrompt).catch((/**
                 * @param {?} _
                 * @return {?}
                 */
                function (_) {
                    _this.debug('Automatic silent refresh did not work');
                }));
            }
        }));
        this.restartRefreshTimerIfStillLoggedIn();
    };
    /**
     * @protected
     * @param {?} params
     * @param {?} noPrompt
     * @return {?}
     */
    OAuthService.prototype.refreshInternal = /**
     * @protected
     * @param {?} params
     * @param {?} noPrompt
     * @return {?}
     */
    function (params, noPrompt) {
        if (this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    OAuthService.prototype.loadDiscoveryDocumentAndTryLogin = /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        return this.loadDiscoveryDocument().then((/**
         * @param {?} doc
         * @return {?}
         */
        function (doc) {
            return _this.tryLogin(options);
        }));
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initImplicitFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initImplicitFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    OAuthService.prototype.loadDiscoveryDocumentAndLogin = /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initImplicitFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        return this.loadDiscoveryDocumentAndTryLogin(options).then((/**
         * @param {?} _
         * @return {?}
         */
        function (_) {
            if (!_this.hasValidIdToken() || !_this.hasValidAccessToken()) {
                _this.initImplicitFlow();
                return false;
            }
            else {
                return true;
            }
        }));
    };
    /**
     * @protected
     * @param {...?} args
     * @return {?}
     */
    OAuthService.prototype.debug = /**
     * @protected
     * @param {...?} args
     * @return {?}
     */
    function () {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        if (this.showDebugInformation) {
            this.logger.debug.apply(console, args);
        }
    };
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    OAuthService.prototype.validateUrlFromDiscoveryDocument = /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    function (url) {
        /** @type {?} */
        var errors = [];
        /** @type {?} */
        var httpsCheck = this.validateUrlForHttps(url);
        /** @type {?} */
        var issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    };
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    OAuthService.prototype.validateUrlForHttps = /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    function (url) {
        if (!url) {
            return true;
        }
        /** @type {?} */
        var lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    };
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    OAuthService.prototype.validateUrlAgainstIssuer = /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    function (url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupRefreshTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e.type === 'token_received'; }))).subscribe((/**
         * @param {?} _
         * @return {?}
         */
        function (_) {
            _this.clearAccessTokenTimer();
            _this.clearIdTokenTimer();
            _this.setupExpirationTimers();
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupExpirationTimers = /**
     * @protected
     * @return {?}
     */
    function () {
        /** @type {?} */
        var idTokenExp = this.getIdTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        var accessTokenExp = this.getAccessTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        var useAccessTokenExp = accessTokenExp <= idTokenExp;
        if (this.hasValidAccessToken() && useAccessTokenExp) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken() && !useAccessTokenExp) {
            this.setupIdTokenTimer();
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupAccessTokenTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        /** @type {?} */
        var expiration = this.getAccessTokenExpiration();
        /** @type {?} */
        var storedAt = this.getAccessTokenStoredAt();
        /** @type {?} */
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
            _this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            function (e) {
                _this.ngZone.run((/**
                 * @return {?}
                 */
                function () {
                    _this.eventsSubject.next(e);
                }));
            }));
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupIdTokenTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        /** @type {?} */
        var expiration = this.getIdTokenExpiration();
        /** @type {?} */
        var storedAt = this.getIdTokenStoredAt();
        /** @type {?} */
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
            _this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            function (e) {
                _this.ngZone.run((/**
                 * @return {?}
                 */
                function () {
                    _this.eventsSubject.next(e);
                }));
            }));
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.clearAccessTokenTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.clearIdTokenTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    };
    /**
     * @protected
     * @param {?} storedAt
     * @param {?} expiration
     * @return {?}
     */
    OAuthService.prototype.calcTimeout = /**
     * @protected
     * @param {?} storedAt
     * @param {?} expiration
     * @return {?}
     */
    function (storedAt, expiration) {
        /** @type {?} */
        var now = Date.now();
        /** @type {?} */
        var delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    };
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param {?} storage
     * @return {?}
     */
    OAuthService.prototype.setStorage = /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param {?} storage
     * @return {?}
     */
    function (storage) {
        this._storage = storage;
        this.configChanged();
    };
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param {?=} fullUrl
     * @return {?}
     */
    OAuthService.prototype.loadDiscoveryDocument = /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param {?=} fullUrl
     * @return {?}
     */
    function (fullUrl) {
        var _this = this;
        if (fullUrl === void 0) { fullUrl = null; }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            if (!fullUrl) {
                fullUrl = _this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!_this.validateUrlForHttps(fullUrl)) {
                reject('issuer must use https, or config value for property requireHttps must allow http');
                return;
            }
            _this.http.get(fullUrl).subscribe((/**
             * @param {?} doc
             * @return {?}
             */
            function (doc) {
                if (!_this.validateDiscoveryDocument(doc)) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                _this.loginUrl = doc.authorization_endpoint;
                _this.logoutUrl = doc.end_session_endpoint || _this.logoutUrl;
                _this.grantTypesSupported = doc.grant_types_supported;
                _this.issuer = doc.issuer;
                _this.tokenEndpoint = doc.token_endpoint;
                _this.userinfoEndpoint = doc.userinfo_endpoint;
                _this.jwksUri = doc.jwks_uri;
                _this.sessionCheckIFrameUrl = doc.check_session_iframe || _this.sessionCheckIFrameUrl;
                _this.discoveryDocumentLoaded = true;
                _this.discoveryDocumentLoadedSubject.next(doc);
                if (_this.sessionChecksEnabled) {
                    _this.restartSessionChecksIfStillLoggedIn();
                }
                _this.loadJwks()
                    .then((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                function (jwks) {
                    /** @type {?} */
                    var result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    /** @type {?} */
                    var event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    _this.eventsSubject.next(event);
                    resolve(event);
                    return;
                }))
                    .catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                function (err) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                }));
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
                _this.logger.error('error loading discovery document', err);
                _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            }));
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.loadJwks = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            if (_this.jwksUri) {
                _this.http.get(_this.jwksUri).subscribe((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                function (jwks) {
                    _this.jwks = jwks;
                    _this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }), (/**
                 * @param {?} err
                 * @return {?}
                 */
                function (err) {
                    _this.logger.error('error loading jwks', err);
                    _this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                }));
            }
            else {
                resolve(null);
            }
        }));
    };
    /**
     * @protected
     * @param {?} doc
     * @return {?}
     */
    OAuthService.prototype.validateDiscoveryDocument = /**
     * @protected
     * @param {?} doc
     * @return {?}
     */
    function (doc) {
        /** @type {?} */
        var errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    };
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlowAndLoadUserProfile = /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then((/**
         * @return {?}
         */
        function () { return _this.loadUserProfile(); }));
    };
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     * @return {?}
     */
    OAuthService.prototype.loadUserProfile = /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     * @return {?}
     */
    function () {
        var _this = this;
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error('userinfoEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            /** @type {?} */
            var headers = new HttpHeaders().set('Authorization', 'Bearer ' + _this.getAccessToken());
            _this.http.get(_this.userinfoEndpoint, { headers: headers }).subscribe((/**
             * @param {?} info
             * @return {?}
             */
            function (info) {
                _this.debug('userinfo received', info);
                /** @type {?} */
                var existingClaims = _this.getIdentityClaims() || {};
                if (!_this.skipSubjectCheck) {
                    if (_this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        /** @type {?} */
                        var err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                _this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                _this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
                _this.logger.error('error loading user info', err);
                _this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            }));
        }));
    };
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlow = /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            var e_1, _a;
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * \@stable
             * @type {?}
             */
            var params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', _this.scope)
                .set('username', userName)
                .set('password', password);
            if (_this.useHttpBasicAuth) {
                /** @type {?} */
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = tslib_1.__values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            function (tokenResponse) {
                _this.debug('tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
                _this.logger.error('Error performing password flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            }));
        }));
    };
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     * @return {?}
     */
    OAuthService.prototype.refreshToken = /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     * @return {?}
     */
    function () {
        var _this = this;
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            var e_2, _a;
            /** @type {?} */
            var params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('client_id', _this.clientId)
                .set('scope', _this.scope)
                .set('refresh_token', _this._storage.getItem('refresh_token'));
            if (_this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = tslib_1.__values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
            /** @type {?} */
            var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .pipe(switchMap((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            function (tokenResponse) {
                if (tokenResponse.id_token) {
                    return from(_this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true))
                        .pipe(tap((/**
                     * @param {?} result
                     * @return {?}
                     */
                    function (result) { return _this.storeIdToken(result); })), map((/**
                     * @param {?} _
                     * @return {?}
                     */
                    function (_) { return tokenResponse; })));
                }
                else {
                    return of(tokenResponse);
                }
            })))
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
                _this.logger.error('Error performing password flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.removeSilentRefreshEventListener = /**
     * @protected
     * @return {?}
     */
    function () {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupSilentRefreshEventListener = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            /** @type {?} */
            var message = _this.processMessageEventMessage(e);
            _this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                onLoginError: (/**
                 * @param {?} err
                 * @return {?}
                 */
                function (err) {
                    _this.eventsSubject.next(new OAuthErrorEvent('silent_refresh_error', err));
                }),
                onTokenReceived: (/**
                 * @return {?}
                 */
                function () {
                    _this.eventsSubject.next(new OAuthSuccessEvent('silently_refreshed'));
                })
            }).catch((/**
             * @param {?} err
             * @return {?}
             */
            function (err) { return _this.debug('tryLogin during silent refresh failed', err); }));
        });
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    };
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     * @param {?=} params
     * @param {?=} noPrompt
     * @return {?}
     */
    OAuthService.prototype.silentRefresh = /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     * @param {?=} params
     * @param {?=} noPrompt
     * @return {?}
     */
    function (params, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        /** @type {?} */
        var claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        /** @type {?} */
        var existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        /** @type {?} */
        var iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        /** @type {?} */
        var redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then((/**
         * @param {?} url
         * @return {?}
         */
        function (url) {
            iframe.setAttribute('src', url);
            if (!_this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        }));
        /** @type {?} */
        var errors = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e instanceof OAuthErrorEvent; })), first());
        /** @type {?} */
        var success = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e.type === 'silently_refreshed'; })), first());
        /** @type {?} */
        var timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            if (e.type === 'silent_refresh_timeout') {
                _this.eventsSubject.next(e);
            }
        })), map((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            if (e instanceof OAuthErrorEvent) {
                throw e;
            }
            return e;
        })))
            .toPromise();
    };
    /**
     * @param {?=} options
     * @return {?}
     */
    OAuthService.prototype.initImplicitFlowInPopup = /**
     * @param {?=} options
     * @return {?}
     */
    function (options) {
        var _this = this;
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then((/**
         * @param {?} url
         * @return {?}
         */
        function (url) {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            function (resolve, reject) {
                /** @type {?} */
                var windowRef = window.open(url, '_blank', _this.calculatePopupFeatures(options));
                /** @type {?} */
                var cleanup = (/**
                 * @return {?}
                 */
                function () {
                    window.removeEventListener('message', listener);
                    windowRef.close();
                    windowRef = null;
                });
                /** @type {?} */
                var listener = (/**
                 * @param {?} e
                 * @return {?}
                 */
                function (e) {
                    /** @type {?} */
                    var message = _this.processMessageEventMessage(e);
                    _this.tryLogin({
                        customHashFragment: message,
                        preventClearHashAfterLogin: true,
                    }).then((/**
                     * @return {?}
                     */
                    function () {
                        cleanup();
                        resolve();
                    }), (/**
                     * @param {?} err
                     * @return {?}
                     */
                    function (err) {
                        cleanup();
                        reject(err);
                    }));
                });
                window.addEventListener('message', listener);
            }));
        }));
    };
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    OAuthService.prototype.calculatePopupFeatures = /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    function (options) {
        // Specify an static height and width and calculate centered position
        /** @type {?} */
        var height = options.height || 470;
        /** @type {?} */
        var width = options.width || 500;
        /** @type {?} */
        var left = (screen.width / 2) - (width / 2);
        /** @type {?} */
        var top = (screen.height / 2) - (height / 2);
        return "location=no,toolbar=no,width=" + width + ",height=" + height + ",top=" + top + ",left=" + left;
    };
    /**
     * @protected
     * @param {?} e
     * @return {?}
     */
    OAuthService.prototype.processMessageEventMessage = /**
     * @protected
     * @param {?} e
     * @return {?}
     */
    function (e) {
        /** @type {?} */
        var expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        /** @type {?} */
        var prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.canPerformSessionCheck = /**
     * @protected
     * @return {?}
     */
    function () {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        /** @type {?} */
        var sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.setupSessionCheckEventListener = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            /** @type {?} */
            var origin = e.origin.toLowerCase();
            /** @type {?} */
            var issuer = _this.issuer.toLowerCase();
            _this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                _this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer);
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    _this.handleSessionUnchanged();
                    break;
                case 'changed':
                    _this.ngZone.run((/**
                     * @return {?}
                     */
                    function () {
                        _this.handleSessionChange();
                    }));
                    break;
                case 'error':
                    _this.ngZone.run((/**
                     * @return {?}
                     */
                    function () {
                        _this.handleSessionError();
                    }));
                    break;
            }
            _this.debug('got info from session check inframe', e);
        });
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
            window.addEventListener('message', _this.sessionCheckEventListener);
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.handleSessionUnchanged = /**
     * @protected
     * @return {?}
     */
    function () {
        this.debug('session check', 'session unchanged');
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.handleSessionChange = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch((/**
             * @param {?} _
             * @return {?}
             */
            function (_) {
                return _this.debug('silent refresh failed after session changed');
            }));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.waitForSilentRefreshAfterSessionChange = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        this.events
            .pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            return e.type === 'silently_refreshed' ||
                e.type === 'silent_refresh_timeout' ||
                e.type === 'silent_refresh_error';
        })), first())
            .subscribe((/**
         * @param {?} e
         * @return {?}
         */
        function (e) {
            if (e.type !== 'silently_refreshed') {
                _this.debug('silent refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            }
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.handleSessionError = /**
     * @protected
     * @return {?}
     */
    function () {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.removeSessionCheckEventListener = /**
     * @protected
     * @return {?}
     */
    function () {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.initSessionCheck = /**
     * @protected
     * @return {?}
     */
    function () {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        /** @type {?} */
        var existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        /** @type {?} */
        var iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        /** @type {?} */
        var url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.startSessionCheckTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        function () {
            _this.sessionCheckTimer = setInterval(_this.checkSession.bind(_this), _this.sessionCheckIntervall);
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.stopSessionCheckTimer = /**
     * @protected
     * @return {?}
     */
    function () {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.checkSession = /**
     * @protected
     * @return {?}
     */
    function () {
        /** @type {?} */
        var iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        /** @type {?} */
        var sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        /** @type {?} */
        var message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    };
    /**
     * @protected
     * @param {?=} state
     * @param {?=} loginHint
     * @param {?=} customRedirectUri
     * @param {?=} noPrompt
     * @param {?=} params
     * @return {?}
     */
    OAuthService.prototype.createLoginUrl = /**
     * @protected
     * @param {?=} state
     * @param {?=} loginHint
     * @param {?=} customRedirectUri
     * @param {?=} noPrompt
     * @param {?=} params
     * @return {?}
     */
    function (state, loginHint, customRedirectUri, noPrompt, params) {
        if (state === void 0) { state = ''; }
        if (loginHint === void 0) { loginHint = ''; }
        if (customRedirectUri === void 0) { customRedirectUri = ''; }
        if (noPrompt === void 0) { noPrompt = false; }
        if (params === void 0) { params = {}; }
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var e_3, _a, e_4, _b, that, redirectUri, nonce, seperationChar, scope, url, _c, challenge, verifier, _d, _e, key, _f, _g, key;
            return tslib_1.__generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        that = this;
                        if (customRedirectUri) {
                            redirectUri = customRedirectUri;
                        }
                        else {
                            redirectUri = this.redirectUri;
                        }
                        return [4 /*yield*/, this.createAndSaveNonce()];
                    case 1:
                        nonce = _h.sent();
                        if (state) {
                            state = nonce + this.config.nonceStateSeparator + state;
                        }
                        else {
                            state = nonce;
                        }
                        if (!this.requestAccessToken && !this.oidc) {
                            throw new Error('Either requestAccessToken or oidc or both must be true');
                        }
                        if (this.config.responseType) {
                            this.responseType = this.config.responseType;
                        }
                        else {
                            if (this.oidc && this.requestAccessToken) {
                                this.responseType = 'id_token token';
                            }
                            else if (this.oidc && !this.requestAccessToken) {
                                this.responseType = 'id_token';
                            }
                            else {
                                this.responseType = 'token';
                            }
                        }
                        seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
                        scope = that.scope;
                        if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                            scope = 'openid ' + scope;
                        }
                        url = that.loginUrl +
                            seperationChar +
                            'response_type=' +
                            encodeURIComponent(that.responseType) +
                            '&client_id=' +
                            encodeURIComponent(that.clientId) +
                            '&state=' +
                            encodeURIComponent(state) +
                            '&redirect_uri=' +
                            encodeURIComponent(redirectUri) +
                            '&scope=' +
                            encodeURIComponent(scope);
                        if (!(this.responseType === 'code' && !this.disablePKCE)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.createChallangeVerifierPairForPKCE()];
                    case 2:
                        _c = tslib_1.__read.apply(void 0, [_h.sent(), 2]), challenge = _c[0], verifier = _c[1];
                        this._storage.setItem('PKCI_verifier', verifier);
                        url += '&code_challenge=' + challenge;
                        url += '&code_challenge_method=S256';
                        _h.label = 3;
                    case 3:
                        if (loginHint) {
                            url += '&login_hint=' + encodeURIComponent(loginHint);
                        }
                        if (that.resource) {
                            url += '&resource=' + encodeURIComponent(that.resource);
                        }
                        if (that.oidc) {
                            url += '&nonce=' + encodeURIComponent(nonce);
                        }
                        if (noPrompt) {
                            url += '&prompt=none';
                        }
                        try {
                            for (_d = tslib_1.__values(Object.keys(params)), _e = _d.next(); !_e.done; _e = _d.next()) {
                                key = _e.value;
                                url +=
                                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
                            }
                        }
                        catch (e_3_1) { e_3 = { error: e_3_1 }; }
                        finally {
                            try {
                                if (_e && !_e.done && (_a = _d.return)) _a.call(_d);
                            }
                            finally { if (e_3) throw e_3.error; }
                        }
                        if (this.customQueryParams) {
                            try {
                                for (_f = tslib_1.__values(Object.getOwnPropertyNames(this.customQueryParams)), _g = _f.next(); !_g.done; _g = _f.next()) {
                                    key = _g.value;
                                    url +=
                                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                                }
                            }
                            catch (e_4_1) { e_4 = { error: e_4_1 }; }
                            finally {
                                try {
                                    if (_g && !_g.done && (_b = _f.return)) _b.call(_f);
                                }
                                finally { if (e_4) throw e_4.error; }
                            }
                        }
                        return [2 /*return*/, url];
                }
            });
        });
    };
    /**
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    OAuthService.prototype.initImplicitFlowInternal = /**
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use https, or config value for property requireHttps must allow http');
        }
        /** @type {?} */
        var addParams = {};
        /** @type {?} */
        var loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            console.error('Error in initImplicitFlow', error);
            _this.inImplicitFlow = false;
        }));
    };
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param {?=} additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param {?=} params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     * @return {?}
     */
    OAuthService.prototype.initImplicitFlow = /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param {?=} additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param {?=} params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     * @return {?}
     */
    function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            function (e) { return e.type === 'discovery_document_loaded'; })))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            function (_) { return _this.initImplicitFlowInternal(additionalState, params); }));
        }
    };
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    /**
     * Reset current implicit flow
     *
     * \@description This method allows resetting the current implict flow in order to be initialized again.
     * @return {?}
     */
    OAuthService.prototype.resetImplicitFlow = /**
     * Reset current implicit flow
     *
     * \@description This method allows resetting the current implict flow in order to be initialized again.
     * @return {?}
     */
    function () {
        this.inImplicitFlow = false;
    };
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    OAuthService.prototype.callOnTokenReceivedIfExists = /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    function (options) {
        /** @type {?} */
        var that = this;
        if (options.onTokenReceived) {
            /** @type {?} */
            var tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    };
    /**
     * @protected
     * @param {?} accessToken
     * @param {?} refreshToken
     * @param {?} expiresIn
     * @param {?} grantedScopes
     * @return {?}
     */
    OAuthService.prototype.storeAccessTokenResponse = /**
     * @protected
     * @param {?} accessToken
     * @param {?} refreshToken
     * @param {?} expiresIn
     * @param {?} grantedScopes
     * @return {?}
     */
    function (accessToken, refreshToken, expiresIn, grantedScopes) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            /** @type {?} */
            var expiresInMilliSeconds = expiresIn * 1000;
            /** @type {?} */
            var now = new Date();
            /** @type {?} */
            var expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
    };
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param {?=} options Optional options.
     * @return {?}
     */
    OAuthService.prototype.tryLogin = /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param {?=} options Optional options.
     * @return {?}
     */
    function (options) {
        if (options === void 0) { options = null; }
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow().then((/**
             * @param {?} _
             * @return {?}
             */
            function (_) { return true; }));
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    };
    /**
     * @private
     * @param {?} queryString
     * @return {?}
     */
    OAuthService.prototype.parseQueryString = /**
     * @private
     * @param {?} queryString
     * @return {?}
     */
    function (queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    /**
     * @return {?}
     */
    OAuthService.prototype.tryLoginCodeFlow = /**
     * @return {?}
     */
    function () {
        var _this = this;
        /** @type {?} */
        var parts = this.parseQueryString(window.location.search);
        /** @type {?} */
        var code = parts['code'];
        /** @type {?} */
        var state = parts['state'];
        /** @type {?} */
        var href = location.href
            .replace(/[&\?]code=[^&\$]*/, '')
            .replace(/[&\?]scope=[^&\$]*/, '')
            .replace(/[&\?]state=[^&\$]*/, '')
            .replace(/[&\?]session_state=[^&\$]*/, '');
        history.replaceState(null, window.name, href);
        var _a = tslib_1.__read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            /** @type {?} */
            var err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        /** @type {?} */
        var success = this.validateNonce(nonceInState);
        if (!success) {
            /** @type {?} */
            var event_1 = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event_1);
            return Promise.reject(event_1);
        }
        if (code) {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            function (resolve, reject) {
                _this.getTokenFromCode(code).then((/**
                 * @param {?} result
                 * @return {?}
                 */
                function (result) {
                    resolve();
                })).catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                function (err) {
                    reject(err);
                }));
            }));
        }
        else {
            return Promise.resolve();
        }
    };
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     * @private
     * @param {?} code
     * @return {?}
     */
    OAuthService.prototype.getTokenFromCode = /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     * @private
     * @param {?} code
     * @return {?}
     */
    function (code) {
        /** @type {?} */
        var params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', this.redirectUri);
        if (!this.disablePKCE) {
            /** @type {?} */
            var pkciVerifier = this._storage.getItem('PKCI_verifier');
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    };
    /**
     * @private
     * @param {?} params
     * @return {?}
     */
    OAuthService.prototype.fetchAndProcessToken = /**
     * @private
     * @param {?} params
     * @return {?}
     */
    function (params) {
        var _this = this;
        /** @type {?} */
        var headers = new HttpHeaders()
            .set('Content-Type', 'application/x-www-form-urlencoded');
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use Http. Also check property requireHttps.');
        }
        if (this.useHttpBasicAuth) {
            /** @type {?} */
            var header = btoa(this.clientId + ":" + this.dummyClientSecret);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        function (resolve, reject) {
            var e_5, _a;
            if (_this.customQueryParams) {
                try {
                    for (var _b = tslib_1.__values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_5_1) { e_5 = { error: e_5_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_5) throw e_5.error; }
                }
            }
            _this.http.post(_this.tokenEndpoint, params, { headers: headers }).subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                if (_this.oidc && tokenResponse.id_token) {
                    _this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then((/**
                     * @param {?} result
                     * @return {?}
                     */
                    function (result) {
                        _this.storeIdToken(result);
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    }))
                        .catch((/**
                     * @param {?} reason
                     * @return {?}
                     */
                    function (reason) {
                        _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    }));
                }
                else {
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }), (/**
             * @param {?} err
             * @return {?}
             */
            function (err) {
                console.error('Error getting token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    };
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param {?=} options Optional options.
     * @return {?}
     */
    OAuthService.prototype.tryLoginImplicitFlow = /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param {?=} options Optional options.
     * @return {?}
     */
    function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        options = options || {};
        /** @type {?} */
        var parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        /** @type {?} */
        var state = parts['state'];
        var _a = tslib_1.__read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            /** @type {?} */
            var err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        var accessToken = parts['access_token'];
        /** @type {?} */
        var idToken = parts['id_token'];
        /** @type {?} */
        var sessionState = parts['session_state'];
        /** @type {?} */
        var grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            /** @type {?} */
            var success = this.validateNonce(nonceInState);
            if (!success) {
                /** @type {?} */
                var event_2 = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event_2);
                return Promise.reject(event_2);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then((/**
         * @param {?} result
         * @return {?}
         */
        function (result) {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then((/**
                 * @param {?} _
                 * @return {?}
                 */
                function (_) { return result; }));
            }
            return result;
        }))
            .then((/**
         * @param {?} result
         * @return {?}
         */
        function (result) {
            _this.storeIdToken(result);
            _this.storeSessionState(sessionState);
            if (_this.clearHashAfterLogin) {
                location.hash = '';
            }
            _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            _this.callOnTokenReceivedIfExists(options);
            _this.inImplicitFlow = false;
            return true;
        }))
            .catch((/**
         * @param {?} reason
         * @return {?}
         */
        function (reason) {
            _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            _this.logger.error('Error validating tokens');
            _this.logger.error(reason);
            return Promise.reject(reason);
        }));
    };
    /**
     * @private
     * @param {?} state
     * @return {?}
     */
    OAuthService.prototype.parseState = /**
     * @private
     * @param {?} state
     * @return {?}
     */
    function (state) {
        /** @type {?} */
        var nonce = state;
        /** @type {?} */
        var userState = '';
        if (state) {
            /** @type {?} */
            var idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    };
    /**
     * @protected
     * @param {?} nonceInState
     * @return {?}
     */
    OAuthService.prototype.validateNonce = /**
     * @protected
     * @param {?} nonceInState
     * @return {?}
     */
    function (nonceInState) {
        /** @type {?} */
        var savedNonce = this._storage.getItem('nonce');
        if (savedNonce !== nonceInState) {
            /** @type {?} */
            var err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    };
    /**
     * @protected
     * @param {?} idToken
     * @return {?}
     */
    OAuthService.prototype.storeIdToken = /**
     * @protected
     * @param {?} idToken
     * @return {?}
     */
    function (idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    };
    /**
     * @protected
     * @param {?} sessionState
     * @return {?}
     */
    OAuthService.prototype.storeSessionState = /**
     * @protected
     * @param {?} sessionState
     * @return {?}
     */
    function (sessionState) {
        this._storage.setItem('session_state', sessionState);
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.getSessionState = /**
     * @protected
     * @return {?}
     */
    function () {
        return this._storage.getItem('session_state');
    };
    /**
     * @protected
     * @param {?} options
     * @param {?} parts
     * @return {?}
     */
    OAuthService.prototype.handleLoginError = /**
     * @protected
     * @param {?} options
     * @param {?} parts
     * @return {?}
     */
    function (options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin) {
            location.hash = '';
        }
    };
    /**
     * @ignore
     */
    /**
     * @ignore
     * @param {?} idToken
     * @param {?} accessToken
     * @param {?=} skipNonceCheck
     * @return {?}
     */
    OAuthService.prototype.processIdToken = /**
     * @ignore
     * @param {?} idToken
     * @param {?} accessToken
     * @param {?=} skipNonceCheck
     * @return {?}
     */
    function (idToken, accessToken, skipNonceCheck) {
        var _this = this;
        if (skipNonceCheck === void 0) { skipNonceCheck = false; }
        /** @type {?} */
        var tokenParts = idToken.split('.');
        /** @type {?} */
        var headerBase64 = this.padBase64(tokenParts[0]);
        /** @type {?} */
        var headerJson = b64DecodeUnicode(headerBase64);
        /** @type {?} */
        var header = JSON.parse(headerJson);
        /** @type {?} */
        var claimsBase64 = this.padBase64(tokenParts[1]);
        /** @type {?} */
        var claimsJson = b64DecodeUnicode(claimsBase64);
        /** @type {?} */
        var claims = JSON.parse(claimsJson);
        /** @type {?} */
        var savedNonce = this._storage.getItem('nonce');
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every((/**
             * @param {?} v
             * @return {?}
             */
            function (v) { return v !== _this.clientId; }))) {
                /** @type {?} */
                var err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                /** @type {?} */
                var err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            /** @type {?} */
            var err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            /** @type {?} */
            var err = 'After refreshing, we got an id_token for another user (sub). ' +
                ("Expected sub: " + this.silentRefreshSubject + ", received sub: " + claims['sub']);
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            /** @type {?} */
            var err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            /** @type {?} */
            var err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            /** @type {?} */
            var err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            /** @type {?} */
            var err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        var now = Date.now();
        /** @type {?} */
        var issuedAtMSec = claims.iat * 1000;
        /** @type {?} */
        var expiresAtMSec = claims.exp * 1000;
        /** @type {?} */
        var clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            /** @type {?} */
            var err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        /** @type {?} */
        var validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: (/**
             * @return {?}
             */
            function () { return _this.loadJwks(); })
        };
        return this.checkAtHash(validationParams)
            .then((/**
         * @param {?} atHashValid
         * @return {?}
         */
        function (atHashValid) {
            if (!_this.disableAtHashCheck &&
                _this.requestAccessToken &&
                !atHashValid) {
                /** @type {?} */
                var err = 'Wrong at_hash';
                _this.logger.warn(err);
                return Promise.reject(err);
            }
            return _this.checkSignature(validationParams).then((/**
             * @param {?} _
             * @return {?}
             */
            function (_) {
                /** @type {?} */
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            }));
        }));
    };
    /**
     * Returns the received claims about the user.
     */
    /**
     * Returns the received claims about the user.
     * @return {?}
     */
    OAuthService.prototype.getIdentityClaims = /**
     * Returns the received claims about the user.
     * @return {?}
     */
    function () {
        /** @type {?} */
        var claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    };
    /**
     * Returns the granted scopes from the server.
     */
    /**
     * Returns the granted scopes from the server.
     * @return {?}
     */
    OAuthService.prototype.getGrantedScopes = /**
     * Returns the granted scopes from the server.
     * @return {?}
     */
    function () {
        /** @type {?} */
        var scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    };
    /**
     * Returns the current id_token.
     */
    /**
     * Returns the current id_token.
     * @return {?}
     */
    OAuthService.prototype.getIdToken = /**
     * Returns the current id_token.
     * @return {?}
     */
    function () {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    };
    /**
     * @protected
     * @param {?} base64data
     * @return {?}
     */
    OAuthService.prototype.padBase64 = /**
     * @protected
     * @param {?} base64data
     * @return {?}
     */
    function (base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    };
    /**
     * Returns the current access_token.
     */
    /**
     * Returns the current access_token.
     * @return {?}
     */
    OAuthService.prototype.getAccessToken = /**
     * Returns the current access_token.
     * @return {?}
     */
    function () {
        return this._storage
            ? this._storage.getItem('access_token')
            : null;
    };
    /**
     * @return {?}
     */
    OAuthService.prototype.getRefreshToken = /**
     * @return {?}
     */
    function () {
        return this._storage
            ? this._storage.getItem('refresh_token')
            : null;
    };
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     * @return {?}
     */
    OAuthService.prototype.getAccessTokenExpiration = /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     * @return {?}
     */
    function () {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.getAccessTokenStoredAt = /**
     * @protected
     * @return {?}
     */
    function () {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.getIdTokenStoredAt = /**
     * @protected
     * @return {?}
     */
    function () {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    };
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     * @return {?}
     */
    OAuthService.prototype.getIdTokenExpiration = /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     * @return {?}
     */
    function () {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    };
    /**
     * Checkes, whether there is a valid access_token.
     */
    /**
     * Checkes, whether there is a valid access_token.
     * @return {?}
     */
    OAuthService.prototype.hasValidAccessToken = /**
     * Checkes, whether there is a valid access_token.
     * @return {?}
     */
    function () {
        if (this.getAccessToken()) {
            /** @type {?} */
            var expiresAt = this._storage.getItem('expires_at');
            /** @type {?} */
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Checks whether there is a valid id_token.
     */
    /**
     * Checks whether there is a valid id_token.
     * @return {?}
     */
    OAuthService.prototype.hasValidIdToken = /**
     * Checks whether there is a valid id_token.
     * @return {?}
     */
    function () {
        if (this.getIdToken()) {
            /** @type {?} */
            var expiresAt = this._storage.getItem('id_token_expires_at');
            /** @type {?} */
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     * @return {?}
     */
    OAuthService.prototype.authorizationHeader = /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     * @return {?}
     */
    function () {
        return 'Bearer ' + this.getAccessToken();
    };
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param noRedirectToLogoutUrl
     */
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param {?=} noRedirectToLogoutUrl
     * @return {?}
     */
    OAuthService.prototype.logOut = /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param {?=} noRedirectToLogoutUrl
     * @return {?}
     */
    function (noRedirectToLogoutUrl) {
        if (noRedirectToLogoutUrl === void 0) { noRedirectToLogoutUrl = false; }
        /** @type {?} */
        var id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        this._storage.removeItem('nonce');
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        /** @type {?} */
        var logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error('logoutUrl must use https, or config value for property requireHttps must allow http');
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            /** @type {?} */
            var params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            /** @type {?} */
            var postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    };
    /**
     * @ignore
     */
    /**
     * @ignore
     * @return {?}
     */
    OAuthService.prototype.createAndSaveNonce = /**
     * @ignore
     * @return {?}
     */
    function () {
        /** @type {?} */
        var that = this;
        return this.createNonce().then((/**
         * @param {?} nonce
         * @return {?}
         */
        function (nonce) {
            that._storage.setItem('nonce', nonce);
            return nonce;
        }));
    };
    /**
     * @ignore
     */
    /**
     * @ignore
     * @return {?}
     */
    OAuthService.prototype.ngOnDestroy = /**
     * @ignore
     * @return {?}
     */
    function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.createNonce = /**
     * @protected
     * @return {?}
     */
    function () {
        var _this = this;
        return new Promise((/**
         * @param {?} resolve
         * @return {?}
         */
        function (resolve) {
            if (_this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
                         * This alphabet uses a-z A-Z 0-9 _- symbols.
                         * Symbols order was changed for better gzip compression.
                         */
            /** @type {?} */
            var url = 'Uint8ArdomValuesObj012345679BCDEFGHIJKLMNPQRSTWXYZ_cfghkpqvwxyz-';
            /** @type {?} */
            var size = 45;
            /** @type {?} */
            var id = '';
            /** @type {?} */
            var crypto = self.crypto || self['msCrypto'];
            if (crypto) {
                /** @type {?} */
                var bytes = crypto.getRandomValues(new Uint8Array(size));
                while (0 < size--) {
                    id += url[bytes[size] & 63];
                }
            }
            else {
                while (0 < size--) {
                    id += url[Math.random() * 64 | 0];
                }
            }
            resolve(id);
        }));
    };
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    OAuthService.prototype.checkAtHash = /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    function (params) {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            return tslib_1.__generator(this, function (_a) {
                if (!this.tokenValidationHandler) {
                    this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                    return [2 /*return*/, true];
                }
                return [2 /*return*/, this.tokenValidationHandler.validateAtHash(params)];
            });
        });
    };
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    OAuthService.prototype.checkSignature = /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    function (params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    };
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    OAuthService.prototype.initLoginFlow = /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    };
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    OAuthService.prototype.initCodeFlow = /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events.pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            function (e) { return e.type === 'discovery_document_loaded'; })))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            function (_) { return _this.initCodeFlowInternal(additionalState, params); }));
        }
    };
    /**
     * @private
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    OAuthService.prototype.initCodeFlowInternal = /**
     * @private
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use Http. Also check property requireHttps.');
        }
        this.createLoginUrl(additionalState, '', null, false, params).then((/**
         * @param {?} url
         * @return {?}
         */
        function (url) {
            console.log("here");
            location.href = url;
        }))
            .catch((/**
         * @param {?} error
         * @return {?}
         */
        function (error) {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        }));
    };
    /**
     * @protected
     * @return {?}
     */
    OAuthService.prototype.createChallangeVerifierPairForPKCE = /**
     * @protected
     * @return {?}
     */
    function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var verifier, challengeRaw, challange;
            return tslib_1.__generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!this.crypto) {
                            throw new Error('PKCI support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
                        }
                        return [4 /*yield*/, this.createNonce()];
                    case 1:
                        verifier = _a.sent();
                        return [4 /*yield*/, this.crypto.calcHash(verifier, 'sha-256')];
                    case 2:
                        challengeRaw = _a.sent();
                        challange = base64UrlEncode(challengeRaw);
                        return [2 /*return*/, [challange, verifier]];
                }
            });
        });
    };
    OAuthService.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    OAuthService.ctorParameters = function () { return [
        { type: NgZone },
        { type: HttpClient },
        { type: OAuthStorage, decorators: [{ type: Optional }] },
        { type: ValidationHandler, decorators: [{ type: Optional }] },
        { type: AuthConfig, decorators: [{ type: Optional }] },
        { type: UrlHelperService },
        { type: OAuthLogger },
        { type: CryptoHandler, decorators: [{ type: Optional }] }
    ]; };
    return OAuthService;
}(AuthConfig));
export { OAuthService };
if (false) {
    /**
     * The ValidationHandler used to validate received
     * id_tokens.
     * @type {?}
     */
    OAuthService.prototype.tokenValidationHandler;
    /**
     * \@internal
     * Deprecated:  use property events instead
     * @type {?}
     */
    OAuthService.prototype.discoveryDocumentLoaded;
    /**
     * \@internal
     * Deprecated:  use property events instead
     * @type {?}
     */
    OAuthService.prototype.discoveryDocumentLoaded$;
    /**
     * Informs about events, like token_received or token_expires.
     * See the string enum EventType for a full list of event types.
     * @type {?}
     */
    OAuthService.prototype.events;
    /**
     * The received (passed around) state, when logging
     * in with implicit flow.
     * @type {?}
     */
    OAuthService.prototype.state;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.eventsSubject;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.discoveryDocumentLoadedSubject;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.silentRefreshPostMessageEventListener;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.grantTypesSupported;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype._storage;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.accessTokenTimeoutSubscription;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.idTokenTimeoutSubscription;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.sessionCheckEventListener;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.jwksUri;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.sessionCheckTimer;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.silentRefreshSubject;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.inImplicitFlow;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.ngZone;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.http;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.config;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.urlHelper;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.logger;
    /**
     * @type {?}
     * @protected
     */
    OAuthService.prototype.crypto;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFhLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBRTNFLE9BQU8sRUFDSCxpQkFBaUIsRUFFcEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUgsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDcEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNILFdBQVcsRUFDWCxZQUFZLEVBTWYsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3BELE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSxtQ0FBbUMsQ0FBQzs7Ozs7O0FBT2xFO0lBQ2tDLHdDQUFVO0lBK0N4QyxzQkFDYyxNQUFjLEVBQ2QsSUFBZ0IsRUFDZCxPQUFxQixFQUNyQixzQkFBeUMsRUFDL0IsTUFB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UUFBUSxDQUFDLFFBQVEsRUFBRSxTQUFTLENBQUMsRUFBQTs7d0JBQTlELFlBQVksR0FBRyxTQUErQzt3QkFDOUQsU0FBUyxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUM7d0JBRS9DLHNCQUFPLENBQUMsU0FBUyxFQUFFLFFBQVEsQ0FBQyxFQUFDOzs7O0tBQ2hDOztnQkFubkVKLFVBQVU7Ozs7Z0JBbkNVLE1BQU07Z0JBQ2xCLFVBQVU7Z0JBaUJmLFlBQVksdUJBb0VQLFFBQVE7Z0JBaEZiLGlCQUFpQix1QkFpRlosUUFBUTtnQkE3RFIsVUFBVSx1QkE4RFYsUUFBUTtnQkEvRVIsZ0JBQWdCO2dCQVFyQixXQUFXO2dCQVdOLGFBQWEsdUJBK0RiLFFBQVE7O0lBNGpFakIsbUJBQUM7Q0FBQSxBQXBuRUQsQ0FDa0MsVUFBVSxHQW1uRTNDO1NBbm5FWSxZQUFZOzs7Ozs7O0lBUXJCLDhDQUFpRDs7Ozs7O0lBTWpELCtDQUF1Qzs7Ozs7O0lBTXZDLGdEQUFvRDs7Ozs7O0lBTXBELDhCQUFzQzs7Ozs7O0lBTXRDLDZCQUFtQjs7Ozs7SUFFbkIscUNBQXlFOzs7OztJQUN6RSxzREFBa0Y7Ozs7O0lBQ2xGLDZEQUErRDs7Ozs7SUFDL0QsMkNBQWtEOzs7OztJQUNsRCxnQ0FBaUM7Ozs7O0lBQ2pDLHNEQUF1RDs7Ozs7SUFDdkQsa0RBQW1EOzs7OztJQUNuRCxpREFBbUQ7Ozs7O0lBQ25ELCtCQUEwQjs7Ozs7SUFDMUIseUNBQWlDOzs7OztJQUNqQyw0Q0FBdUM7Ozs7O0lBQ3ZDLHNDQUFpQzs7Ozs7SUFHN0IsOEJBQXdCOzs7OztJQUN4Qiw0QkFBMEI7Ozs7O0lBRzFCLDhCQUF3Qzs7Ozs7SUFDeEMsaUNBQXFDOzs7OztJQUNyQyw4QkFBNkI7Ozs7O0lBQzdCLDhCQUEyQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE5nWm9uZSwgT3B0aW9uYWwsIE9uRGVzdHJveSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMsIEh0dHBQYXJhbXMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBTdWJqZWN0LCBTdWJzY3JpcHRpb24sIG9mLCByYWNlLCBmcm9tIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBmaWx0ZXIsIGRlbGF5LCBmaXJzdCwgdGFwLCBtYXAsIHN3aXRjaE1hcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcblxuaW1wb3J0IHtcbiAgICBWYWxpZGF0aW9uSGFuZGxlcixcbiAgICBWYWxpZGF0aW9uUGFyYW1zXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcbmltcG9ydCB7XG4gICAgT0F1dGhFdmVudCxcbiAgICBPQXV0aEluZm9FdmVudCxcbiAgICBPQXV0aEVycm9yRXZlbnQsXG4gICAgT0F1dGhTdWNjZXNzRXZlbnRcbn0gZnJvbSAnLi9ldmVudHMnO1xuaW1wb3J0IHtcbiAgICBPQXV0aExvZ2dlcixcbiAgICBPQXV0aFN0b3JhZ2UsXG4gICAgTG9naW5PcHRpb25zLFxuICAgIFBhcnNlZElkVG9rZW4sXG4gICAgT2lkY0Rpc2NvdmVyeURvYyxcbiAgICBUb2tlblJlc3BvbnNlLFxuICAgIFVzZXJJbmZvXG59IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgYjY0RGVjb2RlVW5pY29kZSwgYmFzZTY0VXJsRW5jb2RlIH0gZnJvbSAnLi9iYXNlNjQtaGVscGVyJztcbmltcG9ydCB7IEF1dGhDb25maWcgfSBmcm9tICcuL2F1dGguY29uZmlnJztcbmltcG9ydCB7IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjIH0gZnJvbSAnLi9lbmNvZGVyJztcbmltcG9ydCB7IENyeXB0b0hhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vY3J5cHRvLWhhbmRsZXInO1xuXG4vKipcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcbiAqIE9JREMgYW5kIE9BdXRoMi4gU3VwcG9ydHMgaW1wbGljaXQgZmxvdyBhbmRcbiAqIHBhc3N3b3JkIGZsb3cuXG4gKi9cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBPQXV0aFNlcnZpY2UgZXh0ZW5kcyBBdXRoQ29uZmlnIGltcGxlbWVudHMgT25EZXN0cm95IHtcbiAgICAvLyBFeHRlbmRpbmcgQXV0aENvbmZpZyBpc3QganVzdCBmb3IgTEVHQUNZIHJlYXNvbnNcbiAgICAvLyB0byBub3QgYnJlYWsgZXhpc3RpbmcgY29kZS5cblxuICAgIC8qKlxuICAgICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXG4gICAgICogaWRfdG9rZW5zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSBmYWxzZTtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkOiBPYnNlcnZhYmxlPG9iamVjdD47XG5cbiAgICAvKipcbiAgICAgKiBJbmZvcm1zIGFib3V0IGV2ZW50cywgbGlrZSB0b2tlbl9yZWNlaXZlZCBvciB0b2tlbl9leHBpcmVzLlxuICAgICAqIFNlZSB0aGUgc3RyaW5nIGVudW0gRXZlbnRUeXBlIGZvciBhIGZ1bGwgbGlzdCBvZiBldmVudCB0eXBlcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZXZlbnRzOiBPYnNlcnZhYmxlPE9BdXRoRXZlbnQ+O1xuXG4gICAgLyoqXG4gICAgICogVGhlIHJlY2VpdmVkIChwYXNzZWQgYXJvdW5kKSBzdGF0ZSwgd2hlbiBsb2dnaW5nXG4gICAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxuICAgICAqL1xuICAgIHB1YmxpYyBzdGF0ZT8gPSAnJztcblxuICAgIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcbiAgICBwcm90ZWN0ZWQgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0OiBTdWJqZWN0PG9iamVjdD4gPSBuZXcgU3ViamVjdDxvYmplY3Q+KCk7XG4gICAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gICAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcbiAgICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIHNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gICAgcHJvdGVjdGVkIGp3a3NVcmk6IHN0cmluZztcbiAgICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrVGltZXI6IGFueTtcbiAgICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFN1YmplY3Q6IHN0cmluZztcbiAgICBwcm90ZWN0ZWQgaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcblxuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwcm90ZWN0ZWQgbmdab25lOiBOZ1pvbmUsXG4gICAgICAgIHByb3RlY3RlZCBodHRwOiBIdHRwQ2xpZW50LFxuICAgICAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXG4gICAgICAgIEBPcHRpb25hbCgpIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY29uZmlnOiBBdXRoQ29uZmlnLFxuICAgICAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxuICAgICAgICBwcm90ZWN0ZWQgbG9nZ2VyOiBPQXV0aExvZ2dlcixcbiAgICAgICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNyeXB0bzogQ3J5cHRvSGFuZGxlcixcbiAgICApIHtcbiAgICAgICAgc3VwZXIoKTtcblxuICAgICAgICB0aGlzLmRlYnVnKCdhbmd1bGFyLW9hdXRoMi1vaWRjIHY4LWJldGEnKTtcblxuICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuICAgICAgICB0aGlzLmV2ZW50cyA9IHRoaXMuZXZlbnRzU3ViamVjdC5hc09ic2VydmFibGUoKTtcblxuICAgICAgICBpZiAodG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyID0gdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChjb25maWcpIHtcbiAgICAgICAgICAgIHRoaXMuY29uZmlndXJlKGNvbmZpZyk7XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaWYgKHN0b3JhZ2UpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc3RvcmFnZSk7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc2Vzc2lvblN0b3JhZ2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlKSB7XG5cbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJ1xuICAgICAgICAgICAgICAgICsgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcbiAgICAgICAgICAgICAgICBlXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBjb25maWd1cmUgdGhlIHNlcnZpY2VcbiAgICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXG4gICAgICovXG4gICAgcHVibGljIGNvbmZpZ3VyZShjb25maWc6IEF1dGhDb25maWcpIHtcbiAgICAgICAgLy8gRm9yIHRoZSBzYWtlIG9mIGRvd253YXJkIGNvbXBhdGliaWxpdHkgd2l0aFxuICAgICAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxuICAgICAgICBPYmplY3QuYXNzaWduKHRoaXMsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gICAgfVxuXG4gICAgcHVibGljIHJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2soKSB7XG4gICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXG4gICAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXG4gICAgICogc2lsZW50IHJlZnJlc2hpbmcgd2lsbCBwYXVzZSBhbmQgbm90IHJlZnJlc2ggdGhlIHRva2VucyB1bnRpbCB0aGUgdXNlciBpc1xuICAgICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXG4gICAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXG4gICAgICogQHBhcmFtIGxpc3RlblRvIFNldHVwIGF1dG9tYXRpYyByZWZyZXNoIG9mIGEgc3BlY2lmaWMgdG9rZW4gdHlwZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2gocGFyYW1zOiBvYmplY3QgPSB7fSwgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55Jywgbm9Qcm9tcHQgPSB0cnVlKSB7XG4gICAgICBsZXQgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgICB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICB0YXAoKGUpID0+IHtcbiAgICAgICAgICBpZiAoZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSB7XG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcbiAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ2xvZ291dCcpIHtcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSBmYWxzZTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pLFxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9leHBpcmVzJylcbiAgICAgICkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XG4gICAgICAgIGlmICgobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmIHNob3VsZFJ1blNpbGVudFJlZnJlc2gpIHtcbiAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICB0aGlzLnJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpIHtcbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hUb2tlbigpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXG4gICAgICogZGlyZWN0bHkgY2hhaW5zIHVzaW5nIHRoZSBgdGhlbiguLi4pYCBwYXJ0IG9mIHRoZSBwcm9taXNlIHRvIGNhbGxcbiAgICAgKiB0aGUgYHRyeUxvZ2luKC4uLilgIG1ldGhvZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbiguLi4pYFxuICAgICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdEltcGxpY2l0RmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcbiAgICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kTG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihvcHRpb25zKS50aGVuKF8gPT4ge1xuICAgICAgICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8ICF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgICAgIHRoaXMuaW5pdEltcGxpY2l0RmxvdygpO1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBkZWJ1ZyguLi5hcmdzKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNob3dEZWJ1Z0luZm9ybWF0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5kZWJ1Zy5hcHBseShjb25zb2xlLCBhcmdzKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudCh1cmw6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgICAgICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuICAgICAgICBjb25zdCBodHRwc0NoZWNrID0gdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCk7XG4gICAgICAgIGNvbnN0IGlzc3VlckNoZWNrID0gdGhpcy52YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsKTtcblxuICAgICAgICBpZiAoIWh0dHBzQ2hlY2spIHtcbiAgICAgICAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAgICAgICAgICdodHRwcyBmb3IgYWxsIHVybHMgcmVxdWlyZWQuIEFsc28gZm9yIHVybHMgcmVjZWl2ZWQgYnkgZGlzY292ZXJ5LidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzc3VlckNoZWNrKSB7XG4gICAgICAgICAgICBlcnJvcnMucHVzaChcbiAgICAgICAgICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcbiAgICAgICAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZXJyb3JzO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWlyZUh0dHBzID09PSBmYWxzZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxuICAgICAgICAgICAgICAgIGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykpICYmXG4gICAgICAgICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXG4gICAgICAgICkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbGNVcmwuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybDogc3RyaW5nKSB7XG4gICAgICAgIGlmICghdGhpcy5zdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdXJsLnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aCh0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndGltZXIgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXR0Zm9ybScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwRXhwaXJhdGlvblRpbWVycygpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWRUb2tlbkV4cCA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKSB8fCBOdW1iZXIuTUFYX1ZBTFVFO1xuICAgICAgICBjb25zdCBhY2Nlc3NUb2tlbkV4cCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCkgfHwgTnVtYmVyLk1BWF9WQUxVRTtcbiAgICAgICAgY29uc3QgdXNlQWNjZXNzVG9rZW5FeHAgPSBhY2Nlc3NUb2tlbkV4cCA8PSBpZFRva2VuRXhwO1xuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSAmJiB1c2VBY2Nlc3NUb2tlbkV4cCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpICYmICF1c2VBY2Nlc3NUb2tlbkV4cCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcblxuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdhY2Nlc3NfdG9rZW4nKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTtcbiAgICAgICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldElkVG9rZW5TdG9yZWRBdCgpO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFyQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFySWRUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGNUaW1lb3V0KHN0b3JlZEF0OiBudW1iZXIsIGV4cGlyYXRpb246IG51bWJlcik6IG51bWJlciB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IGRlbHRhID0gKGV4cGlyYXRpb24gLSBzdG9yZWRBdCkgKiB0aGlzLnRpbWVvdXRGYWN0b3IgLSAobm93IC0gc3RvcmVkQXQpO1xuICAgICAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcbiAgICAgKlxuICAgICAqIHsgcHJvdmlkZTogT0F1dGhTdG9yYWdlLCB1c2VGYWN0b3J5OiBvQXV0aFN0b3JhZ2VGYWN0b3J5IH1cbiAgICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XG4gICAgICogU2V0cyBhIGN1c3RvbSBzdG9yYWdlIHVzZWQgdG8gc3RvcmUgdGhlIHJlY2VpdmVkXG4gICAgICogdG9rZW5zIG9uIGNsaWVudCBzaWRlLiBCeSBkZWZhdWx0LCB0aGUgYnJvd3NlcidzXG4gICAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cbiAgICAgKiBAaWdub3JlXG4gICAgICpcbiAgICAgKiBAcGFyYW0gc3RvcmFnZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXRTdG9yYWdlKHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlID0gc3RvcmFnZTtcbiAgICAgICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxuICAgICAqIHByb3BlcnRpZXMgb2YgdGhpcyBzZXJ2aWNlLiBUaGUgdXJsIG9mIHRoZSBkaXNjb3ZlcnlcbiAgICAgKiBkb2N1bWVudCBpcyBpbmZlcmVkIGZyb20gdGhlIGlzc3VlcidzIHVybCBhY2NvcmRpbmdcbiAgICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxuICAgICAqIGNhbiBwYXNzIGl0IHRvIHRvIG9wdGlvbmFsIHBhcmFtZXRlciBmdWxsVXJsLlxuICAgICAqXG4gICAgICogQHBhcmFtIGZ1bGxVcmxcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50KGZ1bGxVcmw6IHN0cmluZyA9IG51bGwpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKCFmdWxsVXJsKSB7XG4gICAgICAgICAgICAgICAgZnVsbFVybCA9IHRoaXMuaXNzdWVyIHx8ICcnO1xuICAgICAgICAgICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XG4gICAgICAgICAgICAgICAgICAgIGZ1bGxVcmwgKz0gJy8nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBmdWxsVXJsICs9ICcud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbic7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKGZ1bGxVcmwpKSB7XG4gICAgICAgICAgICAgICAgcmVqZWN0KCdpc3N1ZXIgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCcpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5odHRwLmdldDxPaWRjRGlzY292ZXJ5RG9jPihmdWxsVXJsKS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgZG9jID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InLCBudWxsKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9naW5VcmwgPSBkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dvdXRVcmwgPSBkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQgfHwgdGhpcy5sb2dvdXRVcmw7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZ3JhbnRUeXBlc1N1cHBvcnRlZCA9IGRvYy5ncmFudF90eXBlc19zdXBwb3J0ZWQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuaXNzdWVyID0gZG9jLmlzc3VlcjtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy50b2tlbkVuZHBvaW50ID0gZG9jLnRva2VuX2VuZHBvaW50O1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnVzZXJpbmZvRW5kcG9pbnQgPSBkb2MudXNlcmluZm9fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuandrc1VyaSA9IGRvYy5qd2tzX3VyaTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPSBkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUgfHwgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0Lm5leHQoZG9jKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2FkSndrcygpXG4gICAgICAgICAgICAgICAgICAgICAgICAudGhlbihqd2tzID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzY292ZXJ5RG9jdW1lbnQ6IGRvYyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgandrczogandrc1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgbG9hZEp3a3MoKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xuICAgICAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQodGhpcy5qd2tzVXJpKS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIGp3a3MgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShqd2tzKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGp3a3MnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZShudWxsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XG4gICAgICAgIGxldCBlcnJvcnM6IHN0cmluZ1tdO1xuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdpbnZhbGlkIGlzc3VlciBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxuICAgICAgICAgICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGF1dGhvcml6YXRpb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy51c2VyaW5mb19lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdXNlcmluZm9fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JywgZXJyb3JzKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgZGlzY292ZXJ5IGRvY3VtZW50JyArXG4gICAgICAgICAgICAgICAgJyBkb2VzIG5vdCBjb250YWluIGEgY2hlY2tfc2Vzc2lvbl9pZnJhbWUgZmllbGQnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cbiAgICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgICAqIHVzZXMgaXQgdG8gcXVlcnkgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGluIG9yZGVyIHRvIGdldCBpbmZvcm1hdGlvblxuICAgICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxuICAgICAqXG4gICAgICogV2hlbiB1c2luZyB0aGlzLCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXG4gICAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXG4gICAgICogZmFpbC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgICAqIEBwYXJhbSBwYXNzd29yZFxuICAgICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgICAqL1xuICAgIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXG4gICAgICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3codXNlck5hbWUsIHBhc3N3b3JkLCBoZWFkZXJzKS50aGVuKFxuICAgICAgICAgICAgKCkgPT4gdGhpcy5sb2FkVXNlclByb2ZpbGUoKVxuICAgICAgICApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExvYWRzIHRoZSB1c2VyIHByb2ZpbGUgYnkgYWNjZXNzaW5nIHRoZSB1c2VyIGluZm8gZW5kcG9pbnQgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICAgKlxuICAgICAqIFdoZW4gdXNpbmcgdGhpcyB3aXRoIE9BdXRoMiBwYXNzd29yZCBmbG93LCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXG4gICAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uIGZhaWwuXG4gICAgICovXG4gICAgcHVibGljIGxvYWRVc2VyUHJvZmlsZSgpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3VzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHAuZ2V0PFVzZXJJbmZvPih0aGlzLnVzZXJpbmZvRW5kcG9pbnQsIHsgaGVhZGVycyB9KS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgaW5mbyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XG5cbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLnNraXBTdWJqZWN0Q2hlY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGMgJiZcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoIWV4aXN0aW5nQ2xhaW1zWydzdWInXSB8fCBpbmZvLnN1YiAhPT0gZXhpc3RpbmdDbGFpbXNbJ3N1YiddKVxuICAgICAgICAgICAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHByb3BlcnR5IG9pZGMgaXMgdHJ1ZSwgdGhlIHJlY2VpdmVkIHVzZXItaWQgKHN1YikgaGFzIHRvIGJlIHRoZSB1c2VyLWlkICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb2YgdGhlIHVzZXIgdGhhdCBoYXMgbG9nZ2VkIGluIHdpdGggb2lkYy5cXG4nICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaW5mbyA9IE9iamVjdC5hc3NpZ24oe30sIGV4aXN0aW5nQ2xhaW1zLCBpbmZvKTtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShpbmZvKTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIHVzZXIgaW5mbycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cbiAgICAgKiBAcGFyYW0gdXNlck5hbWVcbiAgICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxuICAgICAgICB1c2VyTmFtZTogc3RyaW5nLFxuICAgICAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICAgKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogQSBgSHR0cFBhcmFtZXRlckNvZGVjYCB0aGF0IHVzZXMgYGVuY29kZVVSSUNvbXBvbmVudGAgYW5kIGBkZWNvZGVVUklDb21wb25lbnRgIHRvXG4gICAgICAgICAgICAgKiBzZXJpYWxpemUgYW5kIHBhcnNlIFVSTCBwYXJhbWV0ZXIga2V5cyBhbmQgdmFsdWVzLlxuICAgICAgICAgICAgICpcbiAgICAgICAgICAgICAqIEBzdGFibGVcbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcbiAgICAgICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3Bhc3N3b3JkJylcbiAgICAgICAgICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgICAgICAgICAgLnNldCgndXNlcm5hbWUnLCB1c2VyTmFtZSlcbiAgICAgICAgICAgICAgICAuc2V0KCdwYXNzd29yZCcsIHBhc3N3b3JkKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICAgICAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cFxuICAgICAgICAgICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgdG9rZW4gdXNpbmcgYSByZWZyZXNoX3Rva2VuLlxuICAgICAqIFRoaXMgZG9lcyBub3Qgd29yayBmb3IgaW1wbGljaXQgZmxvdywgYi9jXG4gICAgICogdGhlcmUgaXMgbm8gcmVmcmVzaF90b2tlbiBpbiB0aGlzIGZsb3cuXG4gICAgICogQSBzb2x1dGlvbiBmb3IgdGhpcyBpcyBwcm92aWRlZCBieSB0aGVcbiAgICAgKiBtZXRob2Qgc2lsZW50UmVmcmVzaC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVmcmVzaFRva2VuKCk6IFByb21pc2U8b2JqZWN0PiB7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcbiAgICAgICAgICAgICAgICAuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgICAgICAgICAuc2V0KCdyZWZyZXNoX3Rva2VuJywgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykpO1xuXG4gICAgICAgICAgICBpZiAodGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cFxuICAgICAgICAgICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgICAgICAgICAucGlwZShzd2l0Y2hNYXAodG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZnJvbSh0aGlzLnByb2Nlc3NJZFRva2VuKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLCB0cnVlKSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFwKF8gPT4gdG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIHBhc3N3b3JkIGZsb3cnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgICAgb25Mb2dpbkVycm9yOiBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgb25Ub2tlblJlY2VpdmVkOiAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBnZXQgbmV3IHRva2VucyB3aGVuL2JlZm9yZVxuICAgICAqIHRoZSBleGlzdGluZyB0b2tlbnMgZXhwaXJlLlxuICAgICAqL1xuICAgIHB1YmxpYyBzaWxlbnRSZWZyZXNoKHBhcmFtczogb2JqZWN0ID0ge30sIG5vUHJvbXB0ID0gdHJ1ZSk6IFByb21pc2U8T0F1dGhFdmVudD4ge1xuICAgICAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgICAgICBpZiAodGhpcy51c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2ggJiYgdGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgcGFyYW1zWydpZF90b2tlbl9oaW50J10gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXG4gICAgICAgICk7XG5cbiAgICAgICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBjbGFpbXNbJ3N1YiddO1xuXG4gICAgICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgICAgICBpZnJhbWUuaWQgPSB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lO1xuXG4gICAgICAgIHRoaXMuc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xuICAgICAgICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcblxuICAgICAgICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XG4gICAgICAgICAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGNvbnN0IGVycm9ycyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IG9mKFxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXG4gICAgICAgICkucGlwZShkZWxheSh0aGlzLnNpbGVudFJlZnJlc2hUaW1lb3V0KSk7XG5cbiAgICAgICAgcmV0dXJuIHJhY2UoW2Vycm9ycywgc3VjY2VzcywgdGltZW91dF0pXG4gICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICB0YXAoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0Jykge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KSxcbiAgICAgICAgICAgICAgICBtYXAoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBlO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAudG9Qcm9taXNlKCk7XG4gICAgfVxuXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3dJblBvcHVwKG9wdGlvbnM/OiB7IGhlaWdodD86IG51bWJlciwgd2lkdGg/OiBudW1iZXIgfSkge1xuICAgICAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcbiAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlTG9naW5VcmwobnVsbCwgbnVsbCwgdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmksIGZhbHNlLCB7XG4gICAgICAgICAgICBkaXNwbGF5OiAncG9wdXAnXG4gICAgICAgIH0pLnRoZW4odXJsID0+IHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKHVybCwgJ19ibGFuaycsIHRoaXMuY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zKSk7XG5cbiAgICAgICAgICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93UmVmLmNsb3NlKCk7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIGNvbnN0IGxpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcbiAgICAgICAgICAgICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICAgICAgICAgICAgICB9KS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICAgICAgICAgICAgfSwgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczogeyBoZWlnaHQ/OiBudW1iZXIsIHdpZHRoPzogbnVtYmVyIH0pIHtcbiAgICAgICAgLy8gU3BlY2lmeSBhbiBzdGF0aWMgaGVpZ2h0IGFuZCB3aWR0aCBhbmQgY2FsY3VsYXRlIGNlbnRlcmVkIHBvc2l0aW9uXG4gICAgICAgIGNvbnN0IGhlaWdodCA9IG9wdGlvbnMuaGVpZ2h0IHx8IDQ3MDtcbiAgICAgICAgY29uc3Qgd2lkdGggPSBvcHRpb25zLndpZHRoIHx8IDUwMDtcbiAgICAgICAgY29uc3QgbGVmdCA9IChzY3JlZW4ud2lkdGggLyAyKSAtICh3aWR0aCAvIDIpO1xuICAgICAgICBjb25zdCB0b3AgPSAoc2NyZWVuLmhlaWdodCAvIDIpIC0gKGhlaWdodCAvIDIpO1xuICAgICAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGU6IE1lc3NhZ2VFdmVudCkge1xuICAgICAgICBsZXQgZXhwZWN0ZWRQcmVmaXggPSAnIyc7XG5cbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXgpIHtcbiAgICAgICAgICAgIGV4cGVjdGVkUHJlZml4ICs9IHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWUgfHwgIWUuZGF0YSB8fCB0eXBlb2YgZS5kYXRhICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgcHJlZml4ZWRNZXNzYWdlOiBzdHJpbmcgPSBlLmRhdGE7XG5cbiAgICAgICAgaWYgKCFwcmVmaXhlZE1lc3NhZ2Uuc3RhcnRzV2l0aChleHBlY3RlZFByZWZpeCkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiAnIycgKyBwcmVmaXhlZE1lc3NhZ2Uuc3Vic3RyKGV4cGVjdGVkUHJlZml4Lmxlbmd0aCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uQ2hlY2tJRnJhbWVVcmwnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG4gICAgICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbl9zdGF0ZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIHRoaXMucmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG9yaWdpbiA9IGUub3JpZ2luLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICBjb25zdCBpc3N1ZXIgPSB0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpO1xuXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyk7XG5cbiAgICAgICAgICAgIGlmICghaXNzdWVyLnN0YXJ0c1dpdGgob3JpZ2luKSkge1xuICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoXG4gICAgICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyxcbiAgICAgICAgICAgICAgICAgICAgJ3dyb25nIG9yaWdpbicsXG4gICAgICAgICAgICAgICAgICAgIG9yaWdpbixcbiAgICAgICAgICAgICAgICAgICAgJ2V4cGVjdGVkJyxcbiAgICAgICAgICAgICAgICAgICAgaXNzdWVyXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gb25seSBydW4gaW4gQW5ndWxhciB6b25lIGlmIGl0IGlzICdjaGFuZ2VkJyBvciAnZXJyb3InXG4gICAgICAgICAgICBzd2l0Y2ggKGUuZGF0YSkge1xuICAgICAgICAgICAgICAgIGNhc2UgJ3VuY2hhbmdlZCc6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdjaGFuZ2VkJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkNoYW5nZSgpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnZXJyb3InOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uRXJyb3IoKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdnb3QgaW5mbyBmcm9tIHNlc3Npb24gY2hlY2sgaW5mcmFtZScsIGUpO1xuICAgICAgICB9O1xuXG4gICAgICAgIC8vIHByZXZlbnQgQW5ndWxhciBmcm9tIHJlZnJlc2hpbmcgdGhlIHZpZXcgb24gZXZlcnkgbWVzc2FnZSAocnVucyBpbiBpbnRlcnZhbHMpXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuZGVidWcoJ3Nlc3Npb24gY2hlY2snLCAnc2Vzc2lvbiB1bmNoYW5nZWQnKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICAgICAgLyogZXZlbnRzOiBzZXNzaW9uX2NoYW5nZWQsIHJlbG9naW4sIHN0b3BUaW1lciwgbG9nZ2VkX291dCovXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9jaGFuZ2VkJykpO1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaCgpLmNhdGNoKF8gPT5cbiAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBmYWlsZWQgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJylcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB0aGlzLndhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHdhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCkge1xuICAgICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAgICAgLnBpcGUoXG4gICAgICAgICAgICAgICAgZmlsdGVyKFxuICAgICAgICAgICAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcgfHxcbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnIHx8XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcbiAgICAgICAgICAgICAgICApLFxuICAgICAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKGUudHlwZSAhPT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25FcnJvcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2Vycm9yJykpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKSB7XG4gICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGluaXRTZXNzaW9uQ2hlY2soKTogdm9pZCB7XG4gICAgICAgIGlmICghdGhpcy5jYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcbiAgICAgICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgICAgICBpZnJhbWUuaWQgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWU7XG5cbiAgICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICBjb25zdCB1cmwgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcbiAgICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcbiAgICAgICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XG4gICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcblxuICAgICAgICB0aGlzLnN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IHNldEludGVydmFsKFxuICAgICAgICAgICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uLmJpbmQodGhpcyksXG4gICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJbnRlcnZhbGxcbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja1RpbWVyKSB7XG4gICAgICAgICAgICBjbGVhckludGVydmFsKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpO1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xuICAgICAgICBjb25zdCBpZnJhbWU6IGFueSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZSk7XG5cbiAgICAgICAgaWYgKCFpZnJhbWUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcbiAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuXG4gICAgICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XG4gICAgICAgIGlmcmFtZS5jb250ZW50V2luZG93LnBvc3RNZXNzYWdlKG1lc3NhZ2UsIHRoaXMuaXNzdWVyKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXG4gICAgICAgIHN0YXRlID0gJycsXG4gICAgICAgIGxvZ2luSGludCA9ICcnLFxuICAgICAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxuICAgICAgICBub1Byb21wdCA9IGZhbHNlLFxuICAgICAgICBwYXJhbXM6IG9iamVjdCA9IHt9XG4gICAgKSB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuXG4gICAgICAgIGxldCByZWRpcmVjdFVyaTogc3RyaW5nO1xuXG4gICAgICAgIGlmIChjdXN0b21SZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgcmVkaXJlY3RVcmkgPSBjdXN0b21SZWRpcmVjdFVyaTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG5vbmNlID0gYXdhaXQgdGhpcy5jcmVhdGVBbmRTYXZlTm9uY2UoKTtcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICAgIHN0YXRlID0gbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgc3RhdGU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzdGF0ZSA9IG5vbmNlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyBvciBib3RoIG11c3QgYmUgdHJ1ZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlKSB7XG4gICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHRoaXMub2lkYyAmJiAhdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbic7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHNlcGVyYXRpb25DaGFyID0gdGhhdC5sb2dpblVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JztcblxuICAgICAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xuXG4gICAgICAgIGlmICh0aGlzLm9pZGMgJiYgIXNjb3BlLm1hdGNoKC8oXnxcXHMpb3BlbmlkKCR8XFxzKS8pKSB7XG4gICAgICAgICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IHVybCA9XG4gICAgICAgICAgICB0aGF0LmxvZ2luVXJsICtcbiAgICAgICAgICAgIHNlcGVyYXRpb25DaGFyICtcbiAgICAgICAgICAgICdyZXNwb25zZV90eXBlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXG4gICAgICAgICAgICAnJmNsaWVudF9pZD0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXG4gICAgICAgICAgICAnJnN0YXRlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKSArXG4gICAgICAgICAgICAnJnJlZGlyZWN0X3VyaT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xuICAgICAgICAgICAgJyZzY29wZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgJiYgIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgICAgICAgIGNvbnN0IFtjaGFsbGVuZ2UsIHZlcmlmaWVyXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xuICAgICAgICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcbiAgICAgICAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JztcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChsb2dpbkhpbnQpIHtcbiAgICAgICAgICAgIHVybCArPSAnJmxvZ2luX2hpbnQ9JyArIGVuY29kZVVSSUNvbXBvbmVudChsb2dpbkhpbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcbiAgICAgICAgICAgIHVybCArPSAnJnJlc291cmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNvdXJjZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhhdC5vaWRjKSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZub25jZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG5vbmNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub1Byb21wdCkge1xuICAgICAgICAgICAgdXJsICs9ICcmcHJvbXB0PW5vbmUnO1xuICAgICAgICB9XG5cbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xuICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgJyYnICsgZW5jb2RlVVJJQ29tcG9uZW50KGtleSkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQocGFyYW1zW2tleV0pO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHVybDtcblxuICAgIH1cblxuICAgIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ2xvZ2luVXJsIG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGFkZFBhcmFtczogb2JqZWN0ID0ge307XG4gICAgICAgIGxldCBsb2dpbkhpbnQ6IHN0cmluZyA9IG51bGw7XG5cbiAgICAgICAgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XG4gICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCBsb2dpbkhpbnQsIG51bGwsIGZhbHNlLCBhZGRQYXJhbXMpXG4gICAgICAgICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0cyB0aGUgaW1wbGljaXQgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gYWRkaXRpb25hbFN0YXRlIE9wdGlvbmFsIHN0YXRlIHRoYXQgaXMgcGFzc2VkIGFyb3VuZC5cbiAgICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cbiAgICAgKiBAcGFyYW0gcGFyYW1zIEhhc2ggd2l0aCBhZGRpdGlvbmFsIHBhcmFtZXRlci4gSWYgaXQgaXMgYSBzdHJpbmcsIGl0IGlzIHVzZWQgZm9yIHRoZVxuICAgICAqICAgICAgICAgICAgICAgcGFyYW1ldGVyIGxvZ2luSGludCAoZm9yIHRoZSBzYWtlIG9mIGNvbXBhdGliaWxpdHkgd2l0aCBmb3JtZXIgdmVyc2lvbnMpXG4gICAgICovXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcbiAgICAgKlxuICAgICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XG4gICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zOiBMb2dpbk9wdGlvbnMpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgdGhhdCA9IHRoaXM7XG4gICAgICAgIGlmIChvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCkge1xuICAgICAgICAgICAgY29uc3QgdG9rZW5QYXJhbXMgPSB7XG4gICAgICAgICAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcbiAgICAgICAgICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcbiAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogdGhhdC5nZXRBY2Nlc3NUb2tlbigpLFxuICAgICAgICAgICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgb3B0aW9ucy5vblRva2VuUmVjZWl2ZWQodG9rZW5QYXJhbXMpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICAgICAgcmVmcmVzaFRva2VuOiBzdHJpbmcsXG4gICAgICAgIGV4cGlyZXNJbjogbnVtYmVyLFxuICAgICAgICBncmFudGVkU2NvcGVzOiBTdHJpbmdcbiAgICApOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW4nLCBhY2Nlc3NUb2tlbik7XG4gICAgICAgIGlmIChncmFudGVkU2NvcGVzKSB7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJywgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3Blcy5zcGxpdCgnKycpKSk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcbiAgICAgICAgaWYgKGV4cGlyZXNJbikge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSBub3cuZ2V0VGltZSgpICsgZXhwaXJlc0luTWlsbGlTZWNvbmRzO1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdyZWZyZXNoX3Rva2VuJywgcmVmcmVzaFRva2VuKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlbGVnYXRlcyB0byB0cnlMb2dpbkltcGxpY2l0RmxvdyBmb3IgdGhlIHNha2Ugb2YgY29tcGV0YWJpbGl0eVxuICAgICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAgICovXG4gICAgcHVibGljIHRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkNvZGVGbG93KCkudGhlbihfID0+IHRydWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICB9XG5cblxuICAgIHByaXZhdGUgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICAgICAgaWYgKCFxdWVyeVN0cmluZyB8fCBxdWVyeVN0cmluZy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgICAgIHJldHVybiB7fTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xuICAgICAgICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG5cblxuICAgIH1cblxuICAgIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KCk6IFByb21pc2U8dm9pZD4ge1xuXG4gICAgICAgIGNvbnN0IHBhcnRzID0gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpXG5cbiAgICAgICAgY29uc3QgY29kZSA9IHBhcnRzWydjb2RlJ107XG4gICAgICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XG5cbiAgICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11jb2RlPVteJlxcJF0qLywgJycpXG4gICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2NvcGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNlc3Npb25fc3RhdGU9W14mXFwkXSovLCAnJyk7XG5cbiAgICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xuXG4gICAgICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcbiAgICAgICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcblxuICAgICAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdjb2RlX2Vycm9yJywge30sIHBhcnRzKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghbm9uY2VJblN0YXRlKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG4gICAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNvZGUpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5nZXRUb2tlbkZyb21Db2RlKGNvZGUpLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgICAgICAgIH0pLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHZXQgdG9rZW4gdXNpbmcgYW4gaW50ZXJtZWRpYXRlIGNvZGUuIFdvcmtzIGZvciB0aGUgQXV0aG9yaXphdGlvbiBDb2RlIGZsb3cuXG4gICAgICovXG4gICAgcHJpdmF0ZSBnZXRUb2tlbkZyb21Db2RlKGNvZGU6IHN0cmluZyk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXG4gICAgICAgICAgICAuc2V0KCdjb2RlJywgY29kZSlcbiAgICAgICAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIHRoaXMucmVkaXJlY3RVcmkpO1xuXG4gICAgICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgICAgICAgY29uc3QgcGtjaVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XG5cbiAgICAgICAgICAgIGlmICghcGtjaVZlcmlmaWVyKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NvZGVfdmVyaWZpZXInLCBwa2NpVmVyaWZpZXIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMuZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zKTtcbiAgICB9XG5cbiAgICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8b2JqZWN0PiB7XG5cbiAgICAgICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuc2V0KCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyk7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd0b2tlbkVuZHBvaW50IG11c3QgdXNlIEh0dHAuIEFsc28gY2hlY2sgcHJvcGVydHkgcmVxdWlyZUh0dHBzLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5odHRwLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgKHRva2VuUmVzcG9uc2UpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4odG9rZW5SZXNwb25zZS5pZF90b2tlbiwgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4pLlxuICAgICAgICAgICAgICAgICAgICAgICAgdGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2F0Y2gocmVhc29uID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKHJlYXNvbik7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAoZXJyKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGFyZSB0b2tlbnMgaW4gdGhlIGhhc2ggZnJhZ21lbnRcbiAgICAgKiBhcyBhIHJlc3VsdCBvZiB0aGUgaW1wbGljaXQgZmxvdy4gVGhlc2UgdG9rZW5zIGFyZVxuICAgICAqIHBhcnNlZCwgdmFsaWRhdGVkIGFuZCB1c2VkIHRvIHNpZ24gdGhlIHVzZXIgaW4gdG8gdGhlXG4gICAgICogY3VycmVudCBjbGllbnQuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25hbCBvcHRpb25zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgICAgIGxldCBwYXJ0czogb2JqZWN0O1xuXG4gICAgICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XG5cbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICAgICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcihvcHRpb25zLCBwYXJ0cyk7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcbiAgICAgICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSBwYXJ0c1snc2Vzc2lvbl9zdGF0ZSddO1xuICAgICAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyAob3IgYm90aCkgbXVzdCBiZSB0cnVlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5vaWRjICYmICFpZFRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcbiAgICAgICAgICAgICAgICAnd2VyZSBhY3RpdmF0ZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gYnV0IHRoZSBpZF90b2tlbiAnICtcbiAgICAgICAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrKSB7XG4gICAgICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG5cbiAgICAgICAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgICBudWxsLFxuICAgICAgICAgICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcbiAgICAgICAgICAgICAgICBncmFudGVkU2NvcGVzXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLm9pZGMpIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XG5cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3NJZFRva2VuKGlkVG9rZW4sIGFjY2Vzc1Rva2VuKVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy52YWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gb3B0aW9uc1xuICAgICAgICAgICAgICAgICAgICAgICAgLnZhbGlkYXRpb25IYW5kbGVyKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW46IHJlc3VsdC5pZFRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRlOiBzdGF0ZVxuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuKF8gPT4gcmVzdWx0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG4gICAgICAgICAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xuICAgICAgICAgICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2gocmVhc29uID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcml2YXRlIHBhcnNlU3RhdGUoc3RhdGU6IHN0cmluZyk6IFtzdHJpbmcsIHN0cmluZ10ge1xuICAgICAgICBsZXQgbm9uY2UgPSBzdGF0ZTtcbiAgICAgICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xuXG4gICAgICAgIGlmIChzdGF0ZSkge1xuICAgICAgICAgICAgY29uc3QgaWR4ID0gc3RhdGUuaW5kZXhPZih0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yKTtcbiAgICAgICAgICAgIGlmIChpZHggPiAtMSkge1xuICAgICAgICAgICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XG4gICAgICAgICAgICAgICAgdXNlclN0YXRlID0gc3RhdGUuc3Vic3RyKGlkeCArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IubGVuZ3RoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gW25vbmNlLCB1c2VyU3RhdGVdO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZU5vbmNlKFxuICAgICAgICBub25jZUluU3RhdGU6IHN0cmluZ1xuICAgICk6IGJvb2xlYW4ge1xuICAgICAgICBjb25zdCBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgICAgICBpZiAoc2F2ZWROb25jZSAhPT0gbm9uY2VJblN0YXRlKSB7XG5cbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdWYWxpZGF0aW5nIGFjY2Vzc190b2tlbiBmYWlsZWQsIHdyb25nIHN0YXRlL25vbmNlLic7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbicsIGlkVG9rZW4uaWRUb2tlbik7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdzZXNzaW9uX3N0YXRlJywgc2Vzc2lvblN0YXRlKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0U2Vzc2lvblN0YXRlKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcbiAgICAgICAgaWYgKG9wdGlvbnMub25Mb2dpbkVycm9yKSB7XG4gICAgICAgICAgICBvcHRpb25zLm9uTG9naW5FcnJvcihwYXJ0cyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQGlnbm9yZVxuICAgICAqL1xuICAgIHB1YmxpYyBwcm9jZXNzSWRUb2tlbihcbiAgICAgICAgaWRUb2tlbjogc3RyaW5nLFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICBza2lwTm9uY2VDaGVjayA9IGZhbHNlXG4gICAgKTogUHJvbWlzZTxQYXJzZWRJZFRva2VuPiB7XG4gICAgICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xuICAgICAgICBjb25zdCBoZWFkZXJKc29uID0gYjY0RGVjb2RlVW5pY29kZShoZWFkZXJCYXNlNjQpO1xuICAgICAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xuICAgICAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcbiAgICAgICAgY29uc3QgY2xhaW1zSnNvbiA9IGI2NERlY29kZVVuaWNvZGUoY2xhaW1zQmFzZTY0KTtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcbiAgICAgICAgY29uc3Qgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcblxuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xuICAgICAgICAgICAgaWYgKGNsYWltcy5hdWQuZXZlcnkodiA9PiB2ICE9PSB0aGlzLmNsaWVudElkKSkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQuam9pbignLCcpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZDtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWNsYWltcy5zdWIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICAvKiBGb3Igbm93LCB3ZSBvbmx5IGNoZWNrIHdoZXRoZXIgdGhlIHN1YiBhZ2FpbnN0XG4gICAgICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cbiAgICAgICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXG4gICAgICAgICAqIGluIGV2ZXJ5IG90aGVyIGNhc2UgdG9vLlxuICAgICAgICAgKi9cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9XG4gICAgICAgICAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcbiAgICAgICAgICAgICAgICBgRXhwZWN0ZWQgc3ViOiAke3RoaXMuc2lsZW50UmVmcmVzaFN1YmplY3R9LCByZWNlaXZlZCBzdWI6ICR7XG4gICAgICAgICAgICAgICAgY2xhaW1zWydzdWInXVxuICAgICAgICAgICAgICAgIH1gO1xuXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghY2xhaW1zLmlhdCkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ05vIGlhdCBjbGFpbSBpbiBpZF90b2tlbic7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBpc3N1ZXI6ICcgKyBjbGFpbXMuaXNzO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXNraXBOb25jZUNoZWNrICYmIGNsYWltcy5ub25jZSAhPT0gc2F2ZWROb25jZSkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIG5vbmNlOiAnICsgY2xhaW1zLm5vbmNlO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiZcbiAgICAgICAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXG4gICAgICAgICAgICAhY2xhaW1zWydhdF9oYXNoJ11cbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnQW4gYXRfaGFzaCBpcyBuZWVkZWQhJztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgaXNzdWVkQXRNU2VjID0gY2xhaW1zLmlhdCAqIDEwMDA7XG4gICAgICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcbiAgICAgICAgY29uc3QgY2xvY2tTa2V3SW5NU2VjID0gKHRoaXMuY2xvY2tTa2V3SW5TZWMgfHwgNjAwKSAqIDEwMDA7XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgaXNzdWVkQXRNU2VjIC0gY2xvY2tTa2V3SW5NU2VjID49IG5vdyB8fFxuICAgICAgICAgICAgZXhwaXJlc0F0TVNlYyArIGNsb2NrU2tld0luTVNlYyA8PSBub3dcbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnVG9rZW4gaGFzIGV4cGlyZWQnO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnIpO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcih7XG4gICAgICAgICAgICAgICAgbm93OiBub3csXG4gICAgICAgICAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXG4gICAgICAgICAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMgPSB7XG4gICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgICAgandrczogdGhpcy5qd2tzLFxuICAgICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgICAgbG9hZEtleXM6ICgpID0+IHRoaXMubG9hZEp3a3MoKVxuICAgICAgICB9O1xuXG5cbiAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcylcbiAgICAgICAgICAudGhlbihhdEhhc2hWYWxpZCA9PiB7XG4gICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgICAgICAgICB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJlxuICAgICAgICAgICAgICAhYXRIYXNoVmFsaWRcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xuICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHJlY2VpdmVkIGNsYWltcyBhYm91dCB0aGUgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0SWRlbnRpdHlDbGFpbXMoKTogb2JqZWN0IHtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIGlmICghY2xhaW1zKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0R3JhbnRlZFNjb3BlcygpOiBvYmplY3Qge1xuICAgICAgICBjb25zdCBzY29wZXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgICAgIGlmICghc2NvcGVzKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShzY29wZXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2VcbiAgICAgICAgICAgID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHBhZEJhc2U2NChiYXNlNjRkYXRhKTogc3RyaW5nIHtcbiAgICAgICAgd2hpbGUgKGJhc2U2NGRhdGEubGVuZ3RoICUgNCAhPT0gMCkge1xuICAgICAgICAgICAgYmFzZTY0ZGF0YSArPSAnPSc7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJhc2U2NGRhdGE7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgY3VycmVudCBhY2Nlc3NfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldEFjY2Vzc1Rva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuJylcbiAgICAgICAgICAgIDogbnVsbDtcbiAgICB9XG5cbiAgICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cbiAgICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGlkX3Rva2VuXG4gICAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2tlcywgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGFjY2Vzc190b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaGFzVmFsaWRBY2Nlc3NUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGhhc1ZhbGlkSWRUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgYXV0aC1oZWFkZXIgdGhhdCBjYW4gYmUgdXNlZFxuICAgICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXG4gICAgICovXG4gICAgcHVibGljIGF1dGhvcml6YXRpb25IZWFkZXIoKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmVzIGFsbCB0b2tlbnMgYW5kIGxvZ3MgdGhlIHVzZXIgb3V0LlxuICAgICAqIElmIGEgbG9nb3V0IHVybCBpcyBjb25maWd1cmVkLCB0aGUgdXNlciBpc1xuICAgICAqIHJlZGlyZWN0ZWQgdG8gaXQuXG4gICAgICogQHBhcmFtIG5vUmVkaXJlY3RUb0xvZ291dFVybFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2dPdXQobm9SZWRpcmVjdFRvTG9nb3V0VXJsID0gZmFsc2UpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWRfdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3JlZnJlc2hfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2V4cGlyZXNfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gbnVsbDtcblxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcblxuICAgICAgICBpZiAoIXRoaXMubG9nb3V0VXJsKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFpZF90b2tlbiAmJiAhdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBsb2dvdXRVcmw6IHN0cmluZztcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ291dFVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnbG9nb3V0VXJsIG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRm9yIGJhY2t3YXJkIGNvbXBhdGliaWxpdHlcbiAgICAgICAgaWYgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJ3t7JykgPiAtMSkge1xuICAgICAgICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7aWRfdG9rZW5cXH1cXH0vLCBpZF90b2tlbilcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xuXG4gICAgICAgICAgICBpZiAoaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW4pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBwb3N0TG9nb3V0VXJsID0gdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgICAgIGlmIChwb3N0TG9nb3V0VXJsKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgncG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpJywgcG9zdExvZ291dFVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGxvZ291dFVybCA9XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dvdXRVcmwgK1xuICAgICAgICAgICAgICAgICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgK1xuICAgICAgICAgICAgICAgIHBhcmFtcy50b1N0cmluZygpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuY29uZmlnLm9wZW5VcmkobG9nb3V0VXJsKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlTm9uY2UoKS50aGVuKGZ1bmN0aW9uIChub25jZTogYW55KSB7XG4gICAgICAgICAgICB0aGF0Ll9zdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xuICAgICAgICAgICAgcmV0dXJuIG5vbmNlO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIG5nT25EZXN0cm95KCkge1xuICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNyZWF0ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMucm5nVXJsKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8qXG4gICAgICAgICAgICAgKiBUaGlzIGFscGhhYmV0IHVzZXMgYS16IEEtWiAwLTkgXy0gc3ltYm9scy5cbiAgICAgICAgICAgICAqIFN5bWJvbHMgb3JkZXIgd2FzIGNoYW5nZWQgZm9yIGJldHRlciBnemlwIGNvbXByZXNzaW9uLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBjb25zdCB1cmwgPSAnVWludDhBcmRvbVZhbHVlc09iajAxMjM0NTY3OUJDREVGR0hJSktMTU5QUVJTVFdYWVpfY2ZnaGtwcXZ3eHl6LSc7XG4gICAgICAgICAgICBsZXQgc2l6ZSA9IDQ1O1xuICAgICAgICAgICAgbGV0IGlkID0gJyc7XG5cbiAgICAgICAgICAgIGNvbnN0IGNyeXB0byA9IHNlbGYuY3J5cHRvIHx8IHNlbGZbJ21zQ3J5cHRvJ107XG4gICAgICAgICAgICBpZiAoY3J5cHRvKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgYnl0ZXMgPSBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KHNpemUpKTtcbiAgICAgICAgICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgICAgICAgICAgICBpZCArPSB1cmxbYnl0ZXNbc2l6ZV0gJiA2M107XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgICAgICAgICAgICBpZCArPSB1cmxbTWF0aC5yYW5kb20oKSAqIDY0IHwgMF07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXNvbHZlKGlkKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjaGVja1NpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgc2lnbmF0dXJlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zKTtcbiAgICB9XG5cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0IHRoZSBpbXBsaWNpdCBmbG93IG9yIHRoZSBjb2RlIGZsb3csXG4gICAgICogZGVwZW5kaW5nIG9uIHlvdXIgY29uZmlndXJhdGlvbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdExvZ2luRmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKSB7XG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5pbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuaW5pdEltcGxpY2l0RmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTdGFydHMgdGhlIGF1dGhvcml6YXRpb24gY29kZSBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMgbG9naW4gdXJsLlxuICAgICAqL1xuICAgIHB1YmxpYyBpbml0Q29kZUZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcbiAgICAgICAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcykpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBpbml0Q29kZUZsb3dJbnRlcm5hbChcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKTogdm9pZCB7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignbG9naW5VcmwgbXVzdCB1c2UgSHR0cC4gQWxzbyBjaGVjayBwcm9wZXJ0eSByZXF1aXJlSHR0cHMuJyk7XG4gICAgICAgIH1cblxuXG5cbiAgICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCAnJywgbnVsbCwgZmFsc2UsIHBhcmFtcykudGhlbihmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgICBjb25zb2xlLmxvZyhcImhlcmVcIik7XG5cblxuICAgICAgICAgICAgbG9jYXRpb24uaHJlZiA9IHVybDtcblxuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICAgIH0pO1xuXG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTogUHJvbWlzZTxbc3RyaW5nLCBzdHJpbmddPiB7XG5cbiAgICAgICAgaWYgKCF0aGlzLmNyeXB0bykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdQS0NJIHN1cHBvcnQgZm9yIGNvZGUgZmxvdyBuZWVkcyBhIENyeXB0b0hhbmRlci4gRGlkIHlvdSBpbXBvcnQgdGhlIE9BdXRoTW9kdWxlIHVzaW5nIGZvclJvb3QoKSA/Jyk7XG4gICAgICAgIH1cblxuXG4gICAgICAgIGNvbnN0IHZlcmlmaWVyID0gYXdhaXQgdGhpcy5jcmVhdGVOb25jZSgpO1xuICAgICAgICBjb25zdCBjaGFsbGVuZ2VSYXcgPSBhd2FpdCB0aGlzLmNyeXB0by5jYWxjSGFzaCh2ZXJpZmllciwgJ3NoYS0yNTYnKTtcbiAgICAgICAgY29uc3QgY2hhbGxhbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XG5cbiAgICAgICAgcmV0dXJuIFtjaGFsbGFuZ2UsIHZlcmlmaWVyXTtcbiAgICB9XG59XG4iXX0=