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
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFhLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBRTNFLE9BQU8sRUFDSCxpQkFBaUIsRUFFcEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUgsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDcEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNILFdBQVcsRUFDWCxZQUFZLEVBTWYsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3BELE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSxtQ0FBbUMsQ0FBQzs7Ozs7O0FBT2xFO0lBQ2tDLHdDQUFVO0lBK0N4QyxzQkFDYyxNQUFjLEVBQ2QsSUFBZ0IsRUFDZCxPQUFxQixFQUNyQixzQkFBeUMsRUFDL0IsTUFB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RyxlQUFlLENBQUMsWUFBWSxDQUFDO3dCQUUvQyxzQkFBTyxDQUFDLFNBQVMsRUFBRSxRQUFRLENBQUMsRUFBQzs7OztLQUNoQzs7Z0JBM21FSixVQUFVOzs7O2dCQW5DVSxNQUFNO2dCQUNsQixVQUFVO2dCQWlCZixZQUFZLHVCQW9FUCxRQUFRO2dCQWhGYixpQkFBaUIsdUJBaUZaLFFBQVE7Z0JBN0RSLFVBQVUsdUJBOERWLFFBQVE7Z0JBL0VSLGdCQUFnQjtnQkFRckIsV0FBVztnQkFXTixhQUFhLHVCQStEYixRQUFROztJQW9qRWpCLG1CQUFDO0NBQUEsQUE1bUVELENBQ2tDLFVBQVUsR0EybUUzQztTQTNtRVksWUFBWTs7Ozs7OztJQVFyQiw4Q0FBaUQ7Ozs7OztJQU1qRCwrQ0FBdUM7Ozs7OztJQU12QyxnREFBb0Q7Ozs7OztJQU1wRCw4QkFBc0M7Ozs7OztJQU10Qyw2QkFBbUI7Ozs7O0lBRW5CLHFDQUF5RTs7Ozs7SUFDekUsc0RBQWtGOzs7OztJQUNsRiw2REFBK0Q7Ozs7O0lBQy9ELDJDQUFrRDs7Ozs7SUFDbEQsZ0NBQWlDOzs7OztJQUNqQyxzREFBdUQ7Ozs7O0lBQ3ZELGtEQUFtRDs7Ozs7SUFDbkQsaURBQW1EOzs7OztJQUNuRCwrQkFBMEI7Ozs7O0lBQzFCLHlDQUFpQzs7Ozs7SUFDakMsNENBQXVDOzs7OztJQUN2QyxzQ0FBaUM7Ozs7O0lBRzdCLDhCQUF3Qjs7Ozs7SUFDeEIsNEJBQTBCOzs7OztJQUcxQiw4QkFBd0M7Ozs7O0lBQ3hDLGlDQUFxQzs7Ozs7SUFDckMsOEJBQTZCOzs7OztJQUM3Qiw4QkFBMkMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZ1pvbmUsIE9wdGlvbmFsLCBPbkRlc3Ryb3kgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IEh0dHBDbGllbnQsIEh0dHBIZWFkZXJzLCBIdHRwUGFyYW1zIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgU3ViamVjdCwgU3Vic2NyaXB0aW9uLCBvZiwgcmFjZSwgZnJvbSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHsgZmlsdGVyLCBkZWxheSwgZmlyc3QsIHRhcCwgbWFwLCBzd2l0Y2hNYXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5cbmltcG9ydCB7XG4gICAgVmFsaWRhdGlvbkhhbmRsZXIsXG4gICAgVmFsaWRhdGlvblBhcmFtc1xufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7IFVybEhlbHBlclNlcnZpY2UgfSBmcm9tICcuL3VybC1oZWxwZXIuc2VydmljZSc7XG5pbXBvcnQge1xuICAgIE9BdXRoRXZlbnQsXG4gICAgT0F1dGhJbmZvRXZlbnQsXG4gICAgT0F1dGhFcnJvckV2ZW50LFxuICAgIE9BdXRoU3VjY2Vzc0V2ZW50XG59IGZyb20gJy4vZXZlbnRzJztcbmltcG9ydCB7XG4gICAgT0F1dGhMb2dnZXIsXG4gICAgT0F1dGhTdG9yYWdlLFxuICAgIExvZ2luT3B0aW9ucyxcbiAgICBQYXJzZWRJZFRva2VuLFxuICAgIE9pZGNEaXNjb3ZlcnlEb2MsXG4gICAgVG9rZW5SZXNwb25zZSxcbiAgICBVc2VySW5mb1xufSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XG5pbXBvcnQgeyBBdXRoQ29uZmlnIH0gZnJvbSAnLi9hdXRoLmNvbmZpZyc7XG5pbXBvcnQgeyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYyB9IGZyb20gJy4vZW5jb2Rlcic7XG5pbXBvcnQgeyBDcnlwdG9IYW5kbGVyIH0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL2NyeXB0by1oYW5kbGVyJztcblxuLyoqXG4gKiBTZXJ2aWNlIGZvciBsb2dnaW5nIGluIGFuZCBsb2dnaW5nIG91dCB3aXRoXG4gKiBPSURDIGFuZCBPQXV0aDIuIFN1cHBvcnRzIGltcGxpY2l0IGZsb3cgYW5kXG4gKiBwYXNzd29yZCBmbG93LlxuICovXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XG4gICAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXG4gICAgLy8gdG8gbm90IGJyZWFrIGV4aXN0aW5nIGNvZGUuXG5cbiAgICAvKipcbiAgICAgKiBUaGUgVmFsaWRhdGlvbkhhbmRsZXIgdXNlZCB0byB2YWxpZGF0ZSByZWNlaXZlZFxuICAgICAqIGlkX3Rva2Vucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXI7XG5cbiAgICAvKipcbiAgICAgKiBAaW50ZXJuYWxcbiAgICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAgICovXG4gICAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gZmFsc2U7XG5cbiAgICAvKipcbiAgICAgKiBAaW50ZXJuYWxcbiAgICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAgICovXG4gICAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkJDogT2JzZXJ2YWJsZTxvYmplY3Q+O1xuXG4gICAgLyoqXG4gICAgICogSW5mb3JtcyBhYm91dCBldmVudHMsIGxpa2UgdG9rZW5fcmVjZWl2ZWQgb3IgdG9rZW5fZXhwaXJlcy5cbiAgICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXG4gICAgICovXG4gICAgcHVibGljIGV2ZW50czogT2JzZXJ2YWJsZTxPQXV0aEV2ZW50PjtcblxuICAgIC8qKlxuICAgICAqIFRoZSByZWNlaXZlZCAocGFzc2VkIGFyb3VuZCkgc3RhdGUsIHdoZW4gbG9nZ2luZ1xuICAgICAqIGluIHdpdGggaW1wbGljaXQgZmxvdy5cbiAgICAgKi9cbiAgICBwdWJsaWMgc3RhdGU/ID0gJyc7XG5cbiAgICBwcm90ZWN0ZWQgZXZlbnRzU3ViamVjdDogU3ViamVjdDxPQXV0aEV2ZW50PiA9IG5ldyBTdWJqZWN0PE9BdXRoRXZlbnQ+KCk7XG4gICAgcHJvdGVjdGVkIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdDogU3ViamVjdDxvYmplY3Q+ID0gbmV3IFN1YmplY3Q8b2JqZWN0PigpO1xuICAgIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICAgIHByb3RlY3RlZCBncmFudFR5cGVzU3VwcG9ydGVkOiBBcnJheTxzdHJpbmc+ID0gW107XG4gICAgcHJvdGVjdGVkIF9zdG9yYWdlOiBPQXV0aFN0b3JhZ2U7XG4gICAgcHJvdGVjdGVkIGFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xuICAgIHByb3RlY3RlZCBpZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xuICAgIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICAgIHByb3RlY3RlZCBqd2tzVXJpOiBzdHJpbmc7XG4gICAgcHJvdGVjdGVkIHNlc3Npb25DaGVja1RpbWVyOiBhbnk7XG4gICAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hTdWJqZWN0OiBzdHJpbmc7XG4gICAgcHJvdGVjdGVkIGluSW1wbGljaXRGbG93ID0gZmFsc2U7XG5cbiAgICBjb25zdHJ1Y3RvcihcbiAgICAgICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxuICAgICAgICBwcm90ZWN0ZWQgaHR0cDogSHR0cENsaWVudCxcbiAgICAgICAgQE9wdGlvbmFsKCkgc3RvcmFnZTogT0F1dGhTdG9yYWdlLFxuICAgICAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcbiAgICAgICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNvbmZpZzogQXV0aENvbmZpZyxcbiAgICAgICAgcHJvdGVjdGVkIHVybEhlbHBlcjogVXJsSGVscGVyU2VydmljZSxcbiAgICAgICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXG4gICAgICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjcnlwdG86IENyeXB0b0hhbmRsZXIsXG4gICAgKSB7XG4gICAgICAgIHN1cGVyKCk7XG5cbiAgICAgICAgdGhpcy5kZWJ1ZygnYW5ndWxhci1vYXV0aDItb2lkYyB2OC1iZXRhJyk7XG5cbiAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQgPSB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5hc09ic2VydmFibGUoKTtcbiAgICAgICAgdGhpcy5ldmVudHMgPSB0aGlzLmV2ZW50c1N1YmplY3QuYXNPYnNlcnZhYmxlKCk7XG5cbiAgICAgICAgaWYgKHRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlciA9IHRva2VuVmFsaWRhdGlvbkhhbmRsZXI7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY29uZmlnKSB7XG4gICAgICAgICAgICB0aGlzLmNvbmZpZ3VyZShjb25maWcpO1xuICAgICAgICB9XG5cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGlmIChzdG9yYWdlKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHN0b3JhZ2UpO1xuICAgICAgICAgICAgfSBlbHNlIGlmICh0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHNlc3Npb25TdG9yYWdlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBjYXRjaCAoZSkge1xuXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKFxuICAgICAgICAgICAgICAgICdObyBPQXV0aFN0b3JhZ2UgcHJvdmlkZWQgYW5kIGNhbm5vdCBhY2Nlc3MgZGVmYXVsdCAoc2Vzc2lvblN0b3JhZ2UpLidcbiAgICAgICAgICAgICAgICArICdDb25zaWRlciBwcm92aWRpbmcgYSBjdXN0b20gT0F1dGhTdG9yYWdlIGltcGxlbWVudGF0aW9uIGluIHlvdXIgbW9kdWxlLicsXG4gICAgICAgICAgICAgICAgZVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gY29uZmlndXJlIHRoZSBzZXJ2aWNlXG4gICAgICogQHBhcmFtIGNvbmZpZyB0aGUgY29uZmlndXJhdGlvblxuICAgICAqL1xuICAgIHB1YmxpYyBjb25maWd1cmUoY29uZmlnOiBBdXRoQ29uZmlnKSB7XG4gICAgICAgIC8vIEZvciB0aGUgc2FrZSBvZiBkb3dud2FyZCBjb21wYXRpYmlsaXR5IHdpdGhcbiAgICAgICAgLy8gb3JpZ2luYWwgY29uZmlndXJhdGlvbiBBUElcbiAgICAgICAgT2JqZWN0LmFzc2lnbih0aGlzLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xuXG4gICAgICAgIHRoaXMuY29uZmlnID0gT2JqZWN0LmFzc2lnbih7fSBhcyBBdXRoQ29uZmlnLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICAgICAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY29uZmlnQ2hhbmdlZCgpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xuICAgIH1cblxuICAgIHB1YmxpYyByZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcbiAgICAgICAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrKCkge1xuICAgICAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBXaWxsIHNldHVwIHVwIHNpbGVudCByZWZyZXNoaW5nIGZvciB3aGVuIHRoZSB0b2tlbiBpc1xuICAgICAqIGFib3V0IHRvIGV4cGlyZS4gV2hlbiB0aGUgdXNlciBpcyBsb2dnZWQgb3V0IHZpYSB0aGlzLmxvZ091dCBtZXRob2QsIHRoZVxuICAgICAqIHNpbGVudCByZWZyZXNoaW5nIHdpbGwgcGF1c2UgYW5kIG5vdCByZWZyZXNoIHRoZSB0b2tlbnMgdW50aWwgdGhlIHVzZXIgaXNcbiAgICAgKiBsb2dnZWQgYmFjayBpbiB2aWEgcmVjZWl2aW5nIGEgbmV3IHRva2VuLlxuICAgICAqIEBwYXJhbSBwYXJhbXMgQWRkaXRpb25hbCBwYXJhbWV0ZXIgdG8gcGFzc1xuICAgICAqIEBwYXJhbSBsaXN0ZW5UbyBTZXR1cCBhdXRvbWF0aWMgcmVmcmVzaCBvZiBhIHNwZWNpZmljIHRva2VuIHR5cGVcbiAgICAgKi9cbiAgICBwdWJsaWMgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoKHBhcmFtczogb2JqZWN0ID0ge30sIGxpc3RlblRvPzogJ2FjY2Vzc190b2tlbicgfCAnaWRfdG9rZW4nIHwgJ2FueScsIG5vUHJvbXB0ID0gdHJ1ZSkge1xuICAgICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgICAgdGhpcy5ldmVudHMucGlwZShcbiAgICAgICAgdGFwKChlKSA9PiB7XG4gICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICdsb2dvdXQnKSB7XG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gZmFsc2U7XG4gICAgICAgICAgfVxuICAgICAgICB9KSxcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fZXhwaXJlcycpXG4gICAgICApLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgY29uc3QgZXZlbnQgPSBlIGFzIE9BdXRoSW5mb0V2ZW50O1xuICAgICAgICBpZiAoKGxpc3RlblRvID09IG51bGwgfHwgbGlzdGVuVG8gPT09ICdhbnknIHx8IGV2ZW50LmluZm8gPT09IGxpc3RlblRvKSAmJiBzaG91bGRSdW5TaWxlbnRSZWZyZXNoKSB7XG4gICAgICAgICAgLy8gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xuICAgICAgICAgIHRoaXMucmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnQXV0b21hdGljIHNpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yaycpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgdGhpcy5yZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlZnJlc2hJbnRlcm5hbChwYXJhbXMsIG5vUHJvbXB0KSB7XG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoVG9rZW4oKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50KC4uLilgIGFuZFxuICAgICAqIGRpcmVjdGx5IGNoYWlucyB1c2luZyB0aGUgYHRoZW4oLi4uKWAgcGFydCBvZiB0aGUgcHJvbWlzZSB0byBjYWxsXG4gICAgICogdGhlIGB0cnlMb2dpbiguLi4pYCBtZXRob2QuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudCgpLnRoZW4oZG9jID0+IHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luKG9wdGlvbnMpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4oLi4uKWBcbiAgICAgKiBhbmQgaWYgdGhlbiBjaGFpbnMgdG8gYGluaXRJbXBsaWNpdEZsb3coKWAsIGJ1dCBvbmx5IGlmIHRoZXJlIGlzIG5vIHZhbGlkXG4gICAgICogSWRUb2tlbiBvciBubyB2YWxpZCBBY2Nlc3NUb2tlbi5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZExvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9ucykudGhlbihfID0+IHtcbiAgICAgICAgICAgIGlmICghdGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCAhdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3coKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZGVidWcoLi4uYXJncyk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zaG93RGVidWdJbmZvcm1hdGlvbikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZGVidWcuYXBwbHkoY29uc29sZSwgYXJncyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQodXJsOiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gICAgICAgIGNvbnN0IGVycm9yczogc3RyaW5nW10gPSBbXTtcbiAgICAgICAgY29uc3QgaHR0cHNDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh1cmwpO1xuICAgICAgICBjb25zdCBpc3N1ZXJDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybCk7XG5cbiAgICAgICAgaWYgKCFodHRwc0NoZWNrKSB7XG4gICAgICAgICAgICBlcnJvcnMucHVzaChcbiAgICAgICAgICAgICAgICAnaHR0cHMgZm9yIGFsbCB1cmxzIHJlcXVpcmVkLiBBbHNvIGZvciB1cmxzIHJlY2VpdmVkIGJ5IGRpc2NvdmVyeS4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFpc3N1ZXJDaGVjaykge1xuICAgICAgICAgICAgZXJyb3JzLnB1c2goXG4gICAgICAgICAgICAgICAgJ0V2ZXJ5IHVybCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQgaGFzIHRvIHN0YXJ0IHdpdGggdGhlIGlzc3VlciB1cmwuJyArXG4gICAgICAgICAgICAgICAgJ0Fsc28gc2VlIHByb3BlcnR5IHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbi4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGVycm9ycztcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGb3JIdHRwcyh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBsY1VybCA9IHVybC50b0xvd2VyQ2FzZSgpO1xuXG4gICAgICAgIGlmICh0aGlzLnJlcXVpcmVIdHRwcyA9PT0gZmFsc2UpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgKGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykgfHxcbiAgICAgICAgICAgICAgICBsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pKSAmJlxuICAgICAgICAgICAgdGhpcy5yZXF1aXJlSHR0cHMgPT09ICdyZW1vdGVPbmx5J1xuICAgICAgICApIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGxjVXJsLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmw6IHN0cmluZykge1xuICAgICAgICBpZiAoIXRoaXMuc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwUmVmcmVzaFRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3RpbWVyIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0dGZvcm0nKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKF8gPT4ge1xuICAgICAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cEV4cGlyYXRpb25UaW1lcnMoKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGlkVG9rZW5FeHAgPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCkgfHwgTnVtYmVyLk1BWF9WQUxVRTtcbiAgICAgICAgY29uc3QgYWNjZXNzVG9rZW5FeHAgPSB0aGlzLmdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpIHx8IE51bWJlci5NQVhfVkFMVUU7XG4gICAgICAgIGNvbnN0IHVzZUFjY2Vzc1Rva2VuRXhwID0gYWNjZXNzVG9rZW5FeHAgPD0gaWRUb2tlbkV4cDtcblxuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkgJiYgdXNlQWNjZXNzVG9rZW5FeHApIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSAmJiAhdXNlQWNjZXNzVG9rZW5FeHApIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBJZFRva2VuVGltZXIoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpO1xuICAgICAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnYWNjZXNzX3Rva2VuJylcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBJZFRva2VuVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRJZFRva2VuU3RvcmVkQXQoKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xuXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnaWRfdG9rZW4nKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjbGVhckFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjbGVhcklkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcbiAgICAgICAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYWxjVGltZW91dChzdG9yZWRBdDogbnVtYmVyLCBleHBpcmF0aW9uOiBudW1iZXIpOiBudW1iZXIge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBkZWx0YSA9IChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcbiAgICAgICAgcmV0dXJuIE1hdGgubWF4KDAsIGRlbHRhKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBERVBSRUNBVEVELiBVc2UgYSBwcm92aWRlciBmb3IgT0F1dGhTdG9yYWdlIGluc3RlYWQ6XG4gICAgICpcbiAgICAgKiB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogb0F1dGhTdG9yYWdlRmFjdG9yeSB9XG4gICAgICogZXhwb3J0IGZ1bmN0aW9uIG9BdXRoU3RvcmFnZUZhY3RvcnkoKTogT0F1dGhTdG9yYWdlIHsgcmV0dXJuIGxvY2FsU3RvcmFnZTsgfVxuICAgICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxuICAgICAqIHRva2VucyBvbiBjbGllbnQgc2lkZS4gQnkgZGVmYXVsdCwgdGhlIGJyb3dzZXInc1xuICAgICAqIHNlc3Npb25TdG9yYWdlIGlzIHVzZWQuXG4gICAgICogQGlnbm9yZVxuICAgICAqXG4gICAgICogQHBhcmFtIHN0b3JhZ2VcbiAgICAgKi9cbiAgICBwdWJsaWMgc2V0U3RvcmFnZShzdG9yYWdlOiBPQXV0aFN0b3JhZ2UpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExvYWRzIHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQgdG8gY29uZmlndXJlIG1vc3RcbiAgICAgKiBwcm9wZXJ0aWVzIG9mIHRoaXMgc2VydmljZS4gVGhlIHVybCBvZiB0aGUgZGlzY292ZXJ5XG4gICAgICogZG9jdW1lbnQgaXMgaW5mZXJlZCBmcm9tIHRoZSBpc3N1ZXIncyB1cmwgYWNjb3JkaW5nXG4gICAgICogdG8gdGhlIE9wZW5JZCBDb25uZWN0IHNwZWMuIFRvIHVzZSBhbm90aGVyIHVybCB5b3VcbiAgICAgKiBjYW4gcGFzcyBpdCB0byB0byBvcHRpb25hbCBwYXJhbWV0ZXIgZnVsbFVybC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBmdWxsVXJsXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudChmdWxsVXJsOiBzdHJpbmcgPSBudWxsKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGlmICghZnVsbFVybCkge1xuICAgICAgICAgICAgICAgIGZ1bGxVcmwgPSB0aGlzLmlzc3VlciB8fCAnJztcbiAgICAgICAgICAgICAgICBpZiAoIWZ1bGxVcmwuZW5kc1dpdGgoJy8nKSkge1xuICAgICAgICAgICAgICAgICAgICBmdWxsVXJsICs9ICcvJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZnVsbFVybCArPSAnLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24nO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyhmdWxsVXJsKSkge1xuICAgICAgICAgICAgICAgIHJlamVjdCgnaXNzdWVyIG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQ8T2lkY0Rpc2NvdmVyeURvYz4oZnVsbFVybCkuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgIGRvYyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZURpc2NvdmVyeURvY3VtZW50KGRvYykpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJywgbnVsbClcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2luVXJsID0gZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmdyYW50VHlwZXNTdXBwb3J0ZWQgPSBkb2MuZ3JhbnRfdHlwZXNfc3VwcG9ydGVkO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmlzc3VlciA9IGRvYy5pc3N1ZXI7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy51c2VyaW5mb0VuZHBvaW50ID0gZG9jLnVzZXJpbmZvX2VuZHBvaW50O1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmp3a3NVcmkgPSBkb2Muandrc191cmk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsID0gZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lIHx8IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5uZXh0KGRvYyk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9hZEp3a3MoKVxuICAgICAgICAgICAgICAgICAgICAgICAgLnRoZW4oandrcyA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0OiBvYmplY3QgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpc2NvdmVyeURvY3VtZW50OiBkb2MsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGp3a3M6IGp3a3NcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShldmVudCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgZGlzY292ZXJ5IGRvY3VtZW50JywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGxvYWRKd2tzKCk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZTxvYmplY3Q+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGlmICh0aGlzLmp3a3NVcmkpIHtcbiAgICAgICAgICAgICAgICB0aGlzLmh0dHAuZ2V0KHRoaXMuandrc1VyaSkuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICAgICBqd2tzID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuandrcyA9IGp3a3M7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoandrcyk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBqd2tzJywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2p3a3NfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHJlc29sdmUobnVsbCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZURpc2NvdmVyeURvY3VtZW50KGRvYzogT2lkY0Rpc2NvdmVyeURvYyk6IGJvb2xlYW4ge1xuICAgICAgICBsZXQgZXJyb3JzOiBzdHJpbmdbXTtcblxuICAgICAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGRvYy5pc3N1ZXIgIT09IHRoaXMuaXNzdWVyKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnaW52YWxpZCBpc3N1ZXIgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICAnZXhwZWN0ZWQ6ICcgKyB0aGlzLmlzc3VlcixcbiAgICAgICAgICAgICAgICAnY3VycmVudDogJyArIGRvYy5pc3N1ZXJcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBhdXRob3JpemF0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgZXJyb3JzXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGVuZF9zZXNzaW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgZXJyb3JzXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudG9rZW5fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHRva2VuX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgZXJyb3JzXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudXNlcmluZm9fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHVzZXJpbmZvX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgZXJyb3JzXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2Muandrc191cmkpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciB2YWxpZGF0aW5nIGp3a3NfdXJpIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycm9ycyk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IGRpc2NvdmVyeSBkb2N1bWVudCcgK1xuICAgICAgICAgICAgICAgICcgZG9lcyBub3QgY29udGFpbiBhIGNoZWNrX3Nlc3Npb25faWZyYW1lIGZpZWxkJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuXG4gICAgICogYWNjZXNzX3Rva2VuLiBBZnRlciByZWNlaXZpbmcgdGhlIGFjY2Vzc190b2tlbiwgdGhpcyBtZXRob2RcbiAgICAgKiB1c2VzIGl0IHRvIHF1ZXJ5IHRoZSB1c2VyaW5mbyBlbmRwb2ludCBpbiBvcmRlciB0byBnZXQgaW5mb3JtYXRpb25cbiAgICAgKiBhYm91dCB0aGUgdXNlciBpbiBxdWVzdGlvbi5cbiAgICAgKlxuICAgICAqIFdoZW4gdXNpbmcgdGhpcywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgICAqIE90aGVyd2lzZSBzdHJpY3RlciB2YWxpZGF0aW9ucyB0YWtlIHBsYWNlIHRoYXQgbWFrZSB0aGlzIG9wZXJhdGlvblxuICAgICAqIGZhaWwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXNlck5hbWVcbiAgICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93QW5kTG9hZFVzZXJQcm9maWxlKFxuICAgICAgICB1c2VyTmFtZTogc3RyaW5nLFxuICAgICAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICAgKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KHVzZXJOYW1lLCBwYXNzd29yZCwgaGVhZGVycykudGhlbihcbiAgICAgICAgICAgICgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKClcbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMb2FkcyB0aGUgdXNlciBwcm9maWxlIGJ5IGFjY2Vzc2luZyB0aGUgdXNlciBpbmZvIGVuZHBvaW50IGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXG4gICAgICpcbiAgICAgKiBXaGVuIHVzaW5nIHRoaXMgd2l0aCBPQXV0aDIgcGFzc3dvcmQgZmxvdywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgICAqIE90aGVyd2lzZSBzdHJpY3RlciB2YWxpZGF0aW9ucyB0YWtlIHBsYWNlIHRoYXQgbWFrZSB0aGlzIG9wZXJhdGlvbiBmYWlsLlxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkVXNlclByb2ZpbGUoKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW4gbm90IGxvYWQgVXNlciBQcm9maWxlIHdpdGhvdXQgYWNjZXNzX3Rva2VuJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy51c2VyaW5mb0VuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd1c2VyaW5mb0VuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5odHRwLmdldDxVc2VySW5mbz4odGhpcy51c2VyaW5mb0VuZHBvaW50LCB7IGhlYWRlcnMgfSkuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgIGluZm8gPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCd1c2VyaW5mbyByZWNlaXZlZCcsIGluZm8pO1xuXG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGV4aXN0aW5nQ2xhaW1zID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5za2lwU3ViamVjdENoZWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5vaWRjICYmXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKCFleGlzdGluZ0NsYWltc1snc3ViJ10gfHwgaW5mby5zdWIgIT09IGV4aXN0aW5nQ2xhaW1zWydzdWInXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdpZiBwcm9wZXJ0eSBvaWRjIGlzIHRydWUsIHRoZSByZWNlaXZlZCB1c2VyLWlkIChzdWIpIGhhcyB0byBiZSB0aGUgdXNlci1pZCAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ29mIHRoZSB1c2VyIHRoYXQgaGFzIGxvZ2dlZCBpbiB3aXRoIG9pZGMuXFxuJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdpZiB5b3UgYXJlIG5vdCB1c2luZyBvaWRjIGJ1dCBqdXN0IG9hdXRoMiBwYXNzd29yZCBmbG93IHNldCBvaWRjIHRvIGZhbHNlJztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGluZm8gPSBPYmplY3QuYXNzaWduKHt9LCBleGlzdGluZ0NsYWltcywgaW5mbyk7XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJywgSlNPTi5zdHJpbmdpZnkoaW5mbykpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgIHJlc29sdmUoaW5mbyk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyB1c2VyIGluZm8nLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhbiBhY2Nlc3NfdG9rZW4uXG4gICAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAgICogQHBhcmFtIHBhc3N3b3JkXG4gICAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAgICovXG4gICAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcbiAgICAgICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICAgICAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgICAgICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMudG9rZW5FbmRwb2ludCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAndG9rZW5FbmRwb2ludCBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIEEgYEh0dHBQYXJhbWV0ZXJDb2RlY2AgdGhhdCB1c2VzIGBlbmNvZGVVUklDb21wb25lbnRgIGFuZCBgZGVjb2RlVVJJQ29tcG9uZW50YCB0b1xuICAgICAgICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cbiAgICAgICAgICAgICAqXG4gICAgICAgICAgICAgKiBAc3RhYmxlXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7IGVuY29kZXI6IG5ldyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYygpIH0pXG4gICAgICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdwYXNzd29yZCcpXG4gICAgICAgICAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3VzZXJuYW1lJywgdXNlck5hbWUpXG4gICAgICAgICAgICAgICAgLnNldCgncGFzc3dvcmQnLCBwYXNzd29yZCk7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAgICAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgICAgICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHBcbiAgICAgICAgICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGVcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgcGFzc3dvcmQgZmxvdycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIHRva2VuIHVzaW5nIGEgcmVmcmVzaF90b2tlbi5cbiAgICAgKiBUaGlzIGRvZXMgbm90IHdvcmsgZm9yIGltcGxpY2l0IGZsb3csIGIvY1xuICAgICAqIHRoZXJlIGlzIG5vIHJlZnJlc2hfdG9rZW4gaW4gdGhpcyBmbG93LlxuICAgICAqIEEgc29sdXRpb24gZm9yIHRoaXMgaXMgcHJvdmlkZWQgYnkgdGhlXG4gICAgICogbWV0aG9kIHNpbGVudFJlZnJlc2guXG4gICAgICovXG4gICAgcHVibGljIHJlZnJlc2hUb2tlbigpOiBQcm9taXNlPG9iamVjdD4ge1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMudG9rZW5FbmRwb2ludCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAndG9rZW5FbmRwb2ludCBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxuICAgICAgICAgICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncmVmcmVzaF90b2tlbicpXG4gICAgICAgICAgICAgICAgLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZClcbiAgICAgICAgICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgICAgICAgICAgLnNldCgncmVmcmVzaF90b2tlbicsIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgICAgICAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgICAgICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHBcbiAgICAgICAgICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgICAgICAgICAgLnBpcGUoc3dpdGNoTWFwKHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAodG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZyb20odGhpcy5wcm9jZXNzSWRUb2tlbih0b2tlblJlc3BvbnNlLmlkX3Rva2VuLCB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbiwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLnBpcGUoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcChyZXN1bHQgPT4gdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KSksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hcChfID0+IHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBvZih0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGVcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIpIHtcbiAgICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKFxuICAgICAgICAgICAgICAgICdtZXNzYWdlJyxcbiAgICAgICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcblxuICAgICAgICAgICAgdGhpcy50cnlMb2dpbih7XG4gICAgICAgICAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICAgICAgICAgIG9uTG9naW5FcnJvcjogZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIG9uVG9rZW5SZWNlaXZlZDogKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3NpbGVudGx5X3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KS5jYXRjaChlcnIgPT4gdGhpcy5kZWJ1ZygndHJ5TG9naW4gZHVyaW5nIHNpbGVudCByZWZyZXNoIGZhaWxlZCcsIGVycikpO1xuICAgICAgICB9O1xuXG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKFxuICAgICAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXG4gICAgICAgICk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGVyZm9ybXMgYSBzaWxlbnQgcmVmcmVzaCBmb3IgaW1wbGljaXQgZmxvdy5cbiAgICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gZ2V0IG5ldyB0b2tlbnMgd2hlbi9iZWZvcmVcbiAgICAgKiB0aGUgZXhpc3RpbmcgdG9rZW5zIGV4cGlyZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2lsZW50UmVmcmVzaChwYXJhbXM6IG9iamVjdCA9IHt9LCBub1Byb21wdCA9IHRydWUpOiBQcm9taXNlPE9BdXRoRXZlbnQ+IHtcbiAgICAgICAgY29uc3QgY2xhaW1zOiBvYmplY3QgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XG5cbiAgICAgICAgaWYgKHRoaXMudXNlSWRUb2tlbkhpbnRGb3JTaWxlbnRSZWZyZXNoICYmIHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcbiAgICAgICAgICAgIHBhcmFtc1snaWRfdG9rZW5faGludCddID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignc2lsZW50IHJlZnJlc2ggaXMgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXRmb3JtJyk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZVxuICAgICAgICApO1xuXG4gICAgICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gY2xhaW1zWydzdWInXTtcblxuICAgICAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICAgICAgaWZyYW1lLmlkID0gdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZTtcblxuICAgICAgICB0aGlzLnNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICBjb25zdCByZWRpcmVjdFVyaSA9IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwobnVsbCwgbnVsbCwgcmVkaXJlY3RVcmksIG5vUHJvbXB0LCBwYXJhbXMpLnRoZW4odXJsID0+IHtcbiAgICAgICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG5cbiAgICAgICAgICAgIGlmICghdGhpcy5zaWxlbnRSZWZyZXNoU2hvd0lGcmFtZSkge1xuICAgICAgICAgICAgICAgIGlmcmFtZS5zdHlsZVsnZGlzcGxheSddID0gJ25vbmUnO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuICAgICAgICB9KTtcblxuICAgICAgICBjb25zdCBlcnJvcnMgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXG4gICAgICAgICAgICBmaXJzdCgpXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyksXG4gICAgICAgICAgICBmaXJzdCgpXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSBvZihcbiAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnLCBudWxsKVxuICAgICAgICApLnBpcGUoZGVsYXkodGhpcy5zaWxlbnRSZWZyZXNoVGltZW91dCkpO1xuXG4gICAgICAgIHJldHVybiByYWNlKFtlcnJvcnMsIHN1Y2Nlc3MsIHRpbWVvdXRdKVxuICAgICAgICAgICAgLnBpcGUoXG4gICAgICAgICAgICAgICAgdGFwKGUgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSksXG4gICAgICAgICAgICAgICAgbWFwKGUgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgLnRvUHJvbWlzZSgpO1xuICAgIH1cblxuICAgIHB1YmxpYyBpbml0SW1wbGljaXRGbG93SW5Qb3B1cChvcHRpb25zPzogeyBoZWlnaHQ/OiBudW1iZXIsIHdpZHRoPzogbnVtYmVyIH0pIHtcbiAgICAgICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKG51bGwsIG51bGwsIHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpLCBmYWxzZSwge1xuICAgICAgICAgICAgZGlzcGxheTogJ3BvcHVwJ1xuICAgICAgICB9KS50aGVuKHVybCA9PiB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgICAgIGxldCB3aW5kb3dSZWYgPSB3aW5kb3cub3Blbih1cmwsICdfYmxhbmsnLCB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucykpO1xuXG4gICAgICAgICAgICAgICAgY29uc3QgY2xlYW51cCA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvd1JlZi5jbG9zZSgpO1xuICAgICAgICAgICAgICAgICAgICB3aW5kb3dSZWYgPSBudWxsO1xuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICBjb25zdCBsaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy50cnlMb2dpbih7XG4gICAgICAgICAgICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgICAgICAgICAgICAgfSkudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgICAgICAgIH0sIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYWxjdWxhdGVQb3B1cEZlYXR1cmVzKG9wdGlvbnM6IHsgaGVpZ2h0PzogbnVtYmVyLCB3aWR0aD86IG51bWJlciB9KSB7XG4gICAgICAgIC8vIFNwZWNpZnkgYW4gc3RhdGljIGhlaWdodCBhbmQgd2lkdGggYW5kIGNhbGN1bGF0ZSBjZW50ZXJlZCBwb3NpdGlvblxuICAgICAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XG4gICAgICAgIGNvbnN0IHdpZHRoID0gb3B0aW9ucy53aWR0aCB8fCA1MDA7XG4gICAgICAgIGNvbnN0IGxlZnQgPSAoc2NyZWVuLndpZHRoIC8gMikgLSAod2lkdGggLyAyKTtcbiAgICAgICAgY29uc3QgdG9wID0gKHNjcmVlbi5oZWlnaHQgLyAyKSAtIChoZWlnaHQgLyAyKTtcbiAgICAgICAgcmV0dXJuIGBsb2NhdGlvbj1ubyx0b29sYmFyPW5vLHdpZHRoPSR7d2lkdGh9LGhlaWdodD0ke2hlaWdodH0sdG9wPSR7dG9wfSxsZWZ0PSR7bGVmdH1gO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBwcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlOiBNZXNzYWdlRXZlbnQpIHtcbiAgICAgICAgbGV0IGV4cGVjdGVkUHJlZml4ID0gJyMnO1xuXG4gICAgICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4KSB7XG4gICAgICAgICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFlIHx8ICFlLmRhdGEgfHwgdHlwZW9mIGUuZGF0YSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHByZWZpeGVkTWVzc2FnZTogc3RyaW5nID0gZS5kYXRhO1xuXG4gICAgICAgIGlmICghcHJlZml4ZWRNZXNzYWdlLnN0YXJ0c1dpdGgoZXhwZWN0ZWRQcmVmaXgpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gJyMnICsgcHJlZml4ZWRNZXNzYWdlLnN1YnN0cihleHBlY3RlZFByZWZpeC5sZW5ndGgpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbkNoZWNrSUZyYW1lVXJsJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuICAgICAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25fc3RhdGUnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0eXBlb2YgZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAgICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgY29uc3QgaXNzdWVyID0gdGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKTtcblxuICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xuXG4gICAgICAgICAgICBpZiAoIWlzc3Vlci5zdGFydHNXaXRoKG9yaWdpbikpIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKFxuICAgICAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgICAgICAgICAgICd3cm9uZyBvcmlnaW4nLFxuICAgICAgICAgICAgICAgICAgICBvcmlnaW4sXG4gICAgICAgICAgICAgICAgICAgICdleHBlY3RlZCcsXG4gICAgICAgICAgICAgICAgICAgIGlzc3VlclxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIG9ubHkgcnVuIGluIEFuZ3VsYXIgem9uZSBpZiBpdCBpcyAnY2hhbmdlZCcgb3IgJ2Vycm9yJ1xuICAgICAgICAgICAgc3dpdGNoIChlLmRhdGEpIHtcbiAgICAgICAgICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnY2hhbmdlZCc6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25DaGFuZ2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ2Vycm9yJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkVycm9yKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcbiAgICAgICAgfTtcblxuICAgICAgICAvLyBwcmV2ZW50IEFuZ3VsYXIgZnJvbSByZWZyZXNoaW5nIHRoZSB2aWV3IG9uIGV2ZXJ5IG1lc3NhZ2UgKHJ1bnMgaW4gaW50ZXJ2YWxzKVxuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk6IHZvaWQge1xuICAgICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uIGNoZWNrJywgJ3Nlc3Npb24gdW5jaGFuZ2VkJyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XG4gICAgICAgIC8qIGV2ZW50czogc2Vzc2lvbl9jaGFuZ2VkLCByZWxvZ2luLCBzdG9wVGltZXIsIGxvZ2dlZF9vdXQqL1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fY2hhbmdlZCcpKTtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpKSB7XG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2goKS5jYXRjaChfID0+XG4gICAgICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZmFpbGVkIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgdGhpcy53YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB3YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpIHtcbiAgICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgIGZpbHRlcihcbiAgICAgICAgICAgICAgICAgICAgKGU6IE9BdXRoRXZlbnQpID0+XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRseV9yZWZyZXNoZWQnIHx8XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JyB8fFxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfZXJyb3InXG4gICAgICAgICAgICAgICAgKSxcbiAgICAgICAgICAgICAgICBmaXJzdCgpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgIT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uRXJyb3IoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBpbml0U2Vzc2lvbkNoZWNrKCk6IHZvaWQge1xuICAgICAgICBpZiAoIXRoaXMuY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZSk7XG4gICAgICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICAgICAgaWZyYW1lLmlkID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lO1xuXG4gICAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgY29uc3QgdXJsID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG4gICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG4gICAgICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG5cbiAgICAgICAgdGhpcy5zdGFydFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBzZXRJbnRlcnZhbChcbiAgICAgICAgICAgICAgICB0aGlzLmNoZWNrU2Vzc2lvbi5iaW5kKHRoaXMpLFxuICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSW50ZXJ2YWxsXG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcikge1xuICAgICAgICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNoZWNrU2Vzc2lvbigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWZyYW1lOiBhbnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuXG4gICAgICAgIGlmICghaWZyYW1lKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdjaGVja1Nlc3Npb24gZGlkIG5vdCBmaW5kIGlmcmFtZScsXG4gICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcblxuICAgICAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLmNsaWVudElkICsgJyAnICsgc2Vzc2lvblN0YXRlO1xuICAgICAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUxvZ2luVXJsKFxuICAgICAgICBzdGF0ZSA9ICcnLFxuICAgICAgICBsb2dpbkhpbnQgPSAnJyxcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmkgPSAnJyxcbiAgICAgICAgbm9Qcm9tcHQgPSBmYWxzZSxcbiAgICAgICAgcGFyYW1zOiBvYmplY3QgPSB7fVxuICAgICkge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcblxuICAgICAgICBsZXQgcmVkaXJlY3RVcmk6IHN0cmluZztcblxuICAgICAgICBpZiAoY3VzdG9tUmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBub25jZSA9IGF3YWl0IHRoaXMuY3JlYXRlQW5kU2F2ZU5vbmNlKCk7XG5cbiAgICAgICAgaWYgKHN0YXRlKSB7XG4gICAgICAgICAgICBzdGF0ZSA9IG5vbmNlICsgdGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvciArIHN0YXRlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc3RhdGUgPSBub25jZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIXRoaXMub2lkYykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgb3IgYm90aCBtdXN0IGJlIHRydWUnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xuICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSB0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4gdG9rZW4nO1xuICAgICAgICAgICAgfSBlbHNlIGlmICh0aGlzLm9pZGMgJiYgIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4nO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XG5cbiAgICAgICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcblxuICAgICAgICBpZiAodGhpcy5vaWRjICYmICFzY29wZS5tYXRjaCgvKF58XFxzKW9wZW5pZCgkfFxccykvKSkge1xuICAgICAgICAgICAgc2NvcGUgPSAnb3BlbmlkICcgKyBzY29wZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCB1cmwgPVxuICAgICAgICAgICAgdGhhdC5sb2dpblVybCArXG4gICAgICAgICAgICBzZXBlcmF0aW9uQ2hhciArXG4gICAgICAgICAgICAncmVzcG9uc2VfdHlwZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc3BvbnNlVHlwZSkgK1xuICAgICAgICAgICAgJyZjbGllbnRfaWQ9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xuICAgICAgICAgICAgJyZzdGF0ZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzdGF0ZSkgK1xuICAgICAgICAgICAgJyZyZWRpcmVjdF91cmk9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICtcbiAgICAgICAgICAgICcmc2NvcGU9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xuXG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnICYmICF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICAgICAgICBjb25zdCBbY2hhbGxlbmdlLCB2ZXJpZmllcl0gPSBhd2FpdCB0aGlzLmNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnUEtDSV92ZXJpZmllcicsIHZlcmlmaWVyKTtcbiAgICAgICAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlPScgKyBjaGFsbGVuZ2U7XG4gICAgICAgICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1Nic7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAobG9naW5IaW50KSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZsb2dpbl9oaW50PScgKyBlbmNvZGVVUklDb21wb25lbnQobG9naW5IaW50KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGF0LnJlc291cmNlKSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZyZXNvdXJjZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzb3VyY2UpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoYXQub2lkYykge1xuICAgICAgICAgICAgdXJsICs9ICcmbm9uY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudChub25jZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAobm9Qcm9tcHQpIHtcbiAgICAgICAgICAgIHVybCArPSAnJnByb21wdD1ub25lJztcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKHBhcmFtcykpIHtcbiAgICAgICAgICAgIHVybCArPVxuICAgICAgICAgICAgICAgICcmJyArIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgIHVybCArPVxuICAgICAgICAgICAgICAgICAgICAnJicgKyBrZXkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB1cmw7XG4gICAgICAgIFxuICAgIH1cblxuICAgIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ2xvZ2luVXJsIG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGFkZFBhcmFtczogb2JqZWN0ID0ge307XG4gICAgICAgIGxldCBsb2dpbkhpbnQ6IHN0cmluZyA9IG51bGw7XG5cbiAgICAgICAgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XG4gICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCBsb2dpbkhpbnQsIG51bGwsIGZhbHNlLCBhZGRQYXJhbXMpXG4gICAgICAgICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0cyB0aGUgaW1wbGljaXQgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gYWRkaXRpb25hbFN0YXRlIE9wdGlvbmFsIHN0YXRlIHRoYXQgaXMgcGFzc2VkIGFyb3VuZC5cbiAgICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cbiAgICAgKiBAcGFyYW0gcGFyYW1zIEhhc2ggd2l0aCBhZGRpdGlvbmFsIHBhcmFtZXRlci4gSWYgaXQgaXMgYSBzdHJpbmcsIGl0IGlzIHVzZWQgZm9yIHRoZVxuICAgICAqICAgICAgICAgICAgICAgcGFyYW1ldGVyIGxvZ2luSGludCAoZm9yIHRoZSBzYWtlIG9mIGNvbXBhdGliaWxpdHkgd2l0aCBmb3JtZXIgdmVyc2lvbnMpXG4gICAgICovXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcbiAgICAgKlxuICAgICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XG4gICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zOiBMb2dpbk9wdGlvbnMpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgdGhhdCA9IHRoaXM7XG4gICAgICAgIGlmIChvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCkge1xuICAgICAgICAgICAgY29uc3QgdG9rZW5QYXJhbXMgPSB7XG4gICAgICAgICAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcbiAgICAgICAgICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcbiAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogdGhhdC5nZXRBY2Nlc3NUb2tlbigpLFxuICAgICAgICAgICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgb3B0aW9ucy5vblRva2VuUmVjZWl2ZWQodG9rZW5QYXJhbXMpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICAgICAgcmVmcmVzaFRva2VuOiBzdHJpbmcsXG4gICAgICAgIGV4cGlyZXNJbjogbnVtYmVyLFxuICAgICAgICBncmFudGVkU2NvcGVzOiBTdHJpbmdcbiAgICApOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW4nLCBhY2Nlc3NUb2tlbik7XG4gICAgICAgIGlmIChncmFudGVkU2NvcGVzKSB7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJywgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3Blcy5zcGxpdCgnKycpKSk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcbiAgICAgICAgaWYgKGV4cGlyZXNJbikge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSBub3cuZ2V0VGltZSgpICsgZXhwaXJlc0luTWlsbGlTZWNvbmRzO1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdyZWZyZXNoX3Rva2VuJywgcmVmcmVzaFRva2VuKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlbGVnYXRlcyB0byB0cnlMb2dpbkltcGxpY2l0RmxvdyBmb3IgdGhlIHNha2Ugb2YgY29tcGV0YWJpbGl0eVxuICAgICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAgICovXG4gICAgcHVibGljIHRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkNvZGVGbG93KCkudGhlbihfID0+IHRydWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICB9XG5cblxuICAgIHByaXZhdGUgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICAgICAgaWYgKCFxdWVyeVN0cmluZyB8fCBxdWVyeVN0cmluZy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgICAgIHJldHVybiB7fTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xuICAgICAgICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG5cblxuICAgIH1cblxuICAgIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KCk6IFByb21pc2U8dm9pZD4ge1xuXG4gICAgICAgIGNvbnN0IHBhcnRzID0gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpXG5cbiAgICAgICAgY29uc3QgY29kZSA9IHBhcnRzWydjb2RlJ107XG4gICAgICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XG5cbiAgICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11jb2RlPVteJlxcJF0qLywgJycpXG4gICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2NvcGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNlc3Npb25fc3RhdGU9W14mXFwkXSovLCAnJyk7XG5cbiAgICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xuXG4gICAgICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcbiAgICAgICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcblxuICAgICAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdjb2RlX2Vycm9yJywge30sIHBhcnRzKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghbm9uY2VJblN0YXRlKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG4gICAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNvZGUpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5nZXRUb2tlbkZyb21Db2RlKGNvZGUpLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgICAgICAgIH0pLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHZXQgdG9rZW4gdXNpbmcgYW4gaW50ZXJtZWRpYXRlIGNvZGUuIFdvcmtzIGZvciB0aGUgQXV0aG9yaXphdGlvbiBDb2RlIGZsb3cuXG4gICAgICovXG4gICAgcHJpdmF0ZSBnZXRUb2tlbkZyb21Db2RlKGNvZGU6IHN0cmluZyk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXG4gICAgICAgICAgICAuc2V0KCdjb2RlJywgY29kZSlcbiAgICAgICAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIHRoaXMucmVkaXJlY3RVcmkpO1xuXG4gICAgICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgICAgICAgY29uc3QgcGtjaVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XG5cbiAgICAgICAgICAgIGlmICghcGtjaVZlcmlmaWVyKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NvZGVfdmVyaWZpZXInLCBwa2NpVmVyaWZpZXIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMuZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zKTtcbiAgICB9XG5cbiAgICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8b2JqZWN0PiB7XG5cbiAgICAgICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuc2V0KCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyk7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd0b2tlbkVuZHBvaW50IG11c3QgdXNlIEh0dHAuIEFsc28gY2hlY2sgcHJvcGVydHkgcmVxdWlyZUh0dHBzLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5odHRwLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgKHRva2VuUmVzcG9uc2UpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sIFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLCBcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9jZXNzSWRUb2tlbih0b2tlblJlc3BvbnNlLmlkX3Rva2VuLCB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbikuICBcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpO1xuICAgICAgICAgICAgXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbikpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIHZhbGlkYXRpbmcgdG9rZW5zJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihyZWFzb24pO1xuICAgICAgICAgICAgXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgKGVycikgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBnZXR0aW5nIHRva2VuJywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBhcmUgdG9rZW5zIGluIHRoZSBoYXNoIGZyYWdtZW50XG4gICAgICogYXMgYSByZXN1bHQgb2YgdGhlIGltcGxpY2l0IGZsb3cuIFRoZXNlIHRva2VucyBhcmVcbiAgICAgKiBwYXJzZWQsIHZhbGlkYXRlZCBhbmQgdXNlZCB0byBzaWduIHRoZSB1c2VyIGluIHRvIHRoZVxuICAgICAqIGN1cnJlbnQgY2xpZW50LlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICAgICAgICBsZXQgcGFydHM6IG9iamVjdDtcblxuICAgICAgICBpZiAob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpIHtcbiAgICAgICAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKCk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmRlYnVnKCdwYXJzZWQgdXJsJywgcGFydHMpO1xuXG4gICAgICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XG5cbiAgICAgICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgICAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Iob3B0aW9ucywgcGFydHMpO1xuICAgICAgICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgYWNjZXNzVG9rZW4gPSBwYXJ0c1snYWNjZXNzX3Rva2VuJ107XG4gICAgICAgIGNvbnN0IGlkVG9rZW4gPSBwYXJ0c1snaWRfdG9rZW4nXTtcbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcbiAgICAgICAgY29uc3QgZ3JhbnRlZFNjb3BlcyA9IHBhcnRzWydzY29wZSddO1xuXG4gICAgICAgIGlmICghdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIXRoaXMub2lkYykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KFxuICAgICAgICAgICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgKG9yIGJvdGgpIG11c3QgYmUgdHJ1ZS4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrICYmICFzdGF0ZSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uIGNoZWNrcyAoU2Vzc2lvbiBTdGF0dXMgQ2hhbmdlIE5vdGlmaWNhdGlvbikgJyArXG4gICAgICAgICAgICAgICAgJ3dlcmUgYWN0aXZhdGVkIGluIHRoZSBjb25maWd1cmF0aW9uIGJ1dCB0aGUgaWRfdG9rZW4gJyArXG4gICAgICAgICAgICAgICAgJ2RvZXMgbm90IGNvbnRhaW4gYSBzZXNzaW9uX3N0YXRlIGNsYWltJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xuICAgICAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuXG4gICAgICAgICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgbnVsbCxcbiAgICAgICAgICAgICAgICBwYXJ0c1snZXhwaXJlc19pbiddIHx8IHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXG4gICAgICAgICAgICAgICAgZ3JhbnRlZFNjb3Blc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRydWUpO1xuXG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzSWRUb2tlbihpZFRva2VuLCBhY2Nlc3NUb2tlbilcbiAgICAgICAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9wdGlvbnNcbiAgICAgICAgICAgICAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkQ2xhaW1zOiByZXN1bHQuaWRUb2tlbkNsYWltcyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAudGhlbihfID0+IHJlc3VsdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpO1xuICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlKTtcbiAgICAgICAgICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcbiAgICAgICAgICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihyZWFzb24pO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChyZWFzb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcbiAgICAgICAgbGV0IG5vbmNlID0gc3RhdGU7XG4gICAgICAgIGxldCB1c2VyU3RhdGUgPSAnJztcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICAgIGNvbnN0IGlkeCA9IHN0YXRlLmluZGV4T2YodGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvcik7XG4gICAgICAgICAgICBpZiAoaWR4ID4gLTEpIHtcbiAgICAgICAgICAgICAgICBub25jZSA9IHN0YXRlLnN1YnN0cigwLCBpZHgpO1xuICAgICAgICAgICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIFtub25jZSwgdXNlclN0YXRlXTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShcbiAgICAgICAgbm9uY2VJblN0YXRlOiBzdHJpbmdcbiAgICApOiBib29sZWFuIHtcbiAgICAgICAgY29uc3Qgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcbiAgICAgICAgaWYgKHNhdmVkTm9uY2UgIT09IG5vbmNlSW5TdGF0ZSkge1xuICAgICAgICAgICAgXG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnVmFsaWRhdGluZyBhY2Nlc3NfdG9rZW4gZmFpbGVkLCB3cm9uZyBzdGF0ZS9ub25jZS4nO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnIsIHNhdmVkTm9uY2UsIG5vbmNlSW5TdGF0ZSk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlSWRUb2tlbihpZFRva2VuOiBQYXJzZWRJZFRva2VuKSB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW4nLCBpZFRva2VuLmlkVG9rZW4pO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBpZFRva2VuLmlkVG9rZW5DbGFpbXNKc29uKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JywgJycgKyBpZFRva2VuLmlkVG9rZW5FeHBpcmVzQXQpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScsIHNlc3Npb25TdGF0ZSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZUxvZ2luRXJyb3Iob3B0aW9uczogTG9naW5PcHRpb25zLCBwYXJ0czogb2JqZWN0KTogdm9pZCB7XG4gICAgICAgIGlmIChvcHRpb25zLm9uTG9naW5FcnJvcikge1xuICAgICAgICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgcHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgIGlkVG9rZW46IHN0cmluZyxcbiAgICAgICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICAgICAgc2tpcE5vbmNlQ2hlY2sgPSBmYWxzZVxuICAgICk6IFByb21pc2U8UGFyc2VkSWRUb2tlbj4ge1xuICAgICAgICBjb25zdCB0b2tlblBhcnRzID0gaWRUb2tlbi5zcGxpdCgnLicpO1xuICAgICAgICBjb25zdCBoZWFkZXJCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzBdKTtcbiAgICAgICAgY29uc3QgaGVhZGVySnNvbiA9IGI2NERlY29kZVVuaWNvZGUoaGVhZGVyQmFzZTY0KTtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gSlNPTi5wYXJzZShoZWFkZXJKc29uKTtcbiAgICAgICAgY29uc3QgY2xhaW1zQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1sxXSk7XG4gICAgICAgIGNvbnN0IGNsYWltc0pzb24gPSBiNjREZWNvZGVVbmljb2RlKGNsYWltc0Jhc2U2NCk7XG4gICAgICAgIGNvbnN0IGNsYWltcyA9IEpTT04ucGFyc2UoY2xhaW1zSnNvbik7XG4gICAgICAgIGNvbnN0IHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG5cbiAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoY2xhaW1zLmF1ZCkpIHtcbiAgICAgICAgICAgIGlmIChjbGFpbXMuYXVkLmV2ZXJ5KHYgPT4gdiAhPT0gdGhpcy5jbGllbnRJZCkpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXVkaWVuY2U6ICcgKyBjbGFpbXMuYXVkLmpvaW4oJywnKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAoY2xhaW1zLmF1ZCAhPT0gdGhpcy5jbGllbnRJZCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFjbGFpbXMuc3ViKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnTm8gc3ViIGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgLyogRm9yIG5vdywgd2Ugb25seSBjaGVjayB3aGV0aGVyIHRoZSBzdWIgYWdhaW5zdFxuICAgICAgICAgKiBzaWxlbnRSZWZyZXNoU3ViamVjdCB3aGVuIHNlc3Npb25DaGVja3NFbmFibGVkIGlzIG9uXG4gICAgICAgICAqIFdlIHdpbGwgcmVjb25zaWRlciBpbiBhIGxhdGVyIHZlcnNpb24gdG8gZG8gdGhpc1xuICAgICAgICAgKiBpbiBldmVyeSBvdGhlciBjYXNlIHRvby5cbiAgICAgICAgICovXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiZcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgJiZcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgIT09IGNsYWltc1snc3ViJ11cbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPVxuICAgICAgICAgICAgICAgICdBZnRlciByZWZyZXNoaW5nLCB3ZSBnb3QgYW4gaWRfdG9rZW4gZm9yIGFub3RoZXIgdXNlciAoc3ViKS4gJyArXG4gICAgICAgICAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke1xuICAgICAgICAgICAgICAgIGNsYWltc1snc3ViJ11cbiAgICAgICAgICAgICAgICB9YDtcblxuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWNsYWltcy5pYXQpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGNsYWltcy5pc3MgIT09IHRoaXMuaXNzdWVyKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgaXNzdWVyOiAnICsgY2xhaW1zLmlzcztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFza2lwTm9uY2VDaGVjayAmJiBjbGFpbXMubm9uY2UgIT09IHNhdmVkTm9uY2UpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBub25jZTogJyArIGNsYWltcy5ub25jZTtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXG4gICAgICAgICAgICB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJlxuICAgICAgICAgICAgIWNsYWltc1snYXRfaGFzaCddXG4gICAgICAgICkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ0FuIGF0X2hhc2ggaXMgbmVlZGVkISc7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IGlzc3VlZEF0TVNlYyA9IGNsYWltcy5pYXQgKiAxMDAwO1xuICAgICAgICBjb25zdCBleHBpcmVzQXRNU2VjID0gY2xhaW1zLmV4cCAqIDEwMDA7XG4gICAgICAgIGNvbnN0IGNsb2NrU2tld0luTVNlYyA9ICh0aGlzLmNsb2NrU2tld0luU2VjIHx8IDYwMCkgKiAxMDAwO1xuXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIGlzc3VlZEF0TVNlYyAtIGNsb2NrU2tld0luTVNlYyA+PSBub3cgfHxcbiAgICAgICAgICAgIGV4cGlyZXNBdE1TZWMgKyBjbG9ja1NrZXdJbk1TZWMgPD0gbm93XG4gICAgICAgICkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1Rva2VuIGhhcyBleHBpcmVkJztcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3Ioe1xuICAgICAgICAgICAgICAgIG5vdzogbm93LFxuICAgICAgICAgICAgICAgIGlzc3VlZEF0TVNlYzogaXNzdWVkQXRNU2VjLFxuICAgICAgICAgICAgICAgIGV4cGlyZXNBdE1TZWM6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zID0ge1xuICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICAgIGp3a3M6IHRoaXMuandrcyxcbiAgICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgICAgICAgIGxvYWRLZXlzOiAoKSA9PiB0aGlzLmxvYWRKd2tzKClcbiAgICAgICAgfTtcblxuXG4gICAgICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpXG4gICAgICAgICAgLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiZcbiAgICAgICAgICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcbiAgICAgICAgICAgICAgIWF0SGFzaFZhbGlkXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcbiAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XG4gICAgICAgICAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXG4gICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVySnNvbjogaGVhZGVySnNvbixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICB9KTtcblxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSByZWNlaXZlZCBjbGFpbXMgYWJvdXQgdGhlIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGdldElkZW50aXR5Q2xhaW1zKCk6IG9iamVjdCB7XG4gICAgICAgIGNvbnN0IGNsYWltcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xuICAgICAgICBpZiAoIWNsYWltcykge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UoY2xhaW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBncmFudGVkIHNjb3BlcyBmcm9tIHRoZSBzZXJ2ZXIuXG4gICAgICovXG4gICAgcHVibGljIGdldEdyYW50ZWRTY29wZXMoKTogb2JqZWN0IHtcbiAgICAgICAgY29uc3Qgc2NvcGVzID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgICAgICBpZiAoIXNjb3Blcykge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGlkX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRJZFRva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW4nKVxuICAgICAgICAgICAgOiBudWxsO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBwYWRCYXNlNjQoYmFzZTY0ZGF0YSk6IHN0cmluZyB7XG4gICAgICAgIHdoaWxlIChiYXNlNjRkYXRhLmxlbmd0aCAlIDQgIT09IDApIHtcbiAgICAgICAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBiYXNlNjRkYXRhO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgYWNjZXNzX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZVxuICAgICAgICAgICAgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgcHVibGljIGdldFJlZnJlc2hUb2tlbigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZVxuICAgICAgICAgICAgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAgICAgOiBudWxsO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgYWNjZXNzX3Rva2VuXG4gICAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAgICovXG4gICAgcHVibGljIGdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xuICAgICAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0SWRUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBpZF90b2tlblxuICAgICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRJZFRva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xuICAgICAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrZXMsIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBhY2Nlc3NfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGhhc1ZhbGlkQWNjZXNzVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICh0aGlzLmdldEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGlkX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBoYXNWYWxpZElkVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICh0aGlzLmdldElkVG9rZW4oKSkge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGF1dGgtaGVhZGVyIHRoYXQgY2FuIGJlIHVzZWRcbiAgICAgKiB0byB0cmFuc21pdCB0aGUgYWNjZXNzX3Rva2VuIHRvIGEgc2VydmljZVxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemF0aW9uSGVhZGVyKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cbiAgICAgKiBJZiBhIGxvZ291dCB1cmwgaXMgY29uZmlndXJlZCwgdGhlIHVzZXIgaXNcbiAgICAgKiByZWRpcmVjdGVkIHRvIGl0LlxuICAgICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGlkX3Rva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdyZWZyZXNoX3Rva2VuJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG5cbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XG5cbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdsb2dvdXQnKSk7XG5cbiAgICAgICAgaWYgKCF0aGlzLmxvZ291dFVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIGlmIChub1JlZGlyZWN0VG9Mb2dvdXRVcmwpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaWRfdG9rZW4gJiYgIXRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgbG9nb3V0VXJsOiBzdHJpbmc7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dvdXRVcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ2xvZ291dFVybCBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEZvciBiYWNrd2FyZCBjb21wYXRpYmlsaXR5XG4gICAgICAgIGlmICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCd7eycpID4gLTEpIHtcbiAgICAgICAgICAgIGxvZ291dFVybCA9IHRoaXMubG9nb3V0VXJsXG4gICAgICAgICAgICAgICAgLnJlcGxhY2UoL1xce1xce2lkX3Rva2VuXFx9XFx9LywgaWRfdG9rZW4pXG4gICAgICAgICAgICAgICAgLnJlcGxhY2UoL1xce1xce2NsaWVudF9pZFxcfVxcfS8sIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICB9IGVsc2Uge1xuXG4gICAgICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcblxuICAgICAgICAgICAgaWYgKGlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnaWRfdG9rZW5faGludCcsIGlkX3Rva2VuKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgY29uc3QgcG9zdExvZ291dFVybCA9IHRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICAgICAgICBpZiAocG9zdExvZ291dFVybCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ3Bvc3RfbG9nb3V0X3JlZGlyZWN0X3VyaScsIHBvc3RMb2dvdXRVcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBsb2dvdXRVcmwgPVxuICAgICAgICAgICAgICAgIHRoaXMubG9nb3V0VXJsICtcbiAgICAgICAgICAgICAgICAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPycpICtcbiAgICAgICAgICAgICAgICBwYXJhbXMudG9TdHJpbmcoKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLmNvbmZpZy5vcGVuVXJpKGxvZ291dFVybCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQGlnbm9yZVxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBbmRTYXZlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICAgICAgY29uc3QgdGhhdCA9IHRoaXM7XG4gICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZU5vbmNlKCkudGhlbihmdW5jdGlvbiAobm9uY2U6IGFueSkge1xuICAgICAgICAgICAgdGhhdC5fc3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcbiAgICAgICAgICAgIHJldHVybiBub25jZTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQGlnbm9yZVxuICAgICAqL1xuICAgIHB1YmxpYyBuZ09uRGVzdHJveSgpIHtcbiAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjcmVhdGVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHtcbiAgICAgICAgICAgIGlmICh0aGlzLnJuZ1VybCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAgICAgJ2NyZWF0ZU5vbmNlIHdpdGggcm5nLXdlYi1hcGkgaGFzIG5vdCBiZWVuIGltcGxlbWVudGVkIHNvIGZhcidcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvKlxuICAgICAgICAgICAgICogVGhpcyBhbHBoYWJldCB1c2VzIGEteiBBLVogMC05IF8tIHN5bWJvbHMuXG4gICAgICAgICAgICAgKiBTeW1ib2xzIG9yZGVyIHdhcyBjaGFuZ2VkIGZvciBiZXR0ZXIgZ3ppcCBjb21wcmVzc2lvbi5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgY29uc3QgdXJsID0gJ1VpbnQ4QXJkb21WYWx1ZXNPYmowMTIzNDU2NzlCQ0RFRkdISUpLTE1OUFFSU1RXWFlaX2NmZ2hrcHF2d3h5ei0nO1xuICAgICAgICAgICAgbGV0IHNpemUgPSA0NTtcbiAgICAgICAgICAgIGxldCBpZCA9ICcnO1xuXG4gICAgICAgICAgICBjb25zdCBjcnlwdG8gPSBzZWxmLmNyeXB0byB8fCBzZWxmWydtc0NyeXB0byddO1xuICAgICAgICAgICAgaWYgKGNyeXB0bykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGJ5dGVzID0gY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheShzaXplKSk7XG4gICAgICAgICAgICAgICAgd2hpbGUgKDAgPCBzaXplLS0pIHtcbiAgICAgICAgICAgICAgICAgICAgaWQgKz0gdXJsW2J5dGVzW3NpemVdICYgNjNdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgd2hpbGUgKDAgPCBzaXplLS0pIHtcbiAgICAgICAgICAgICAgICAgICAgaWQgKz0gdXJsW01hdGgucmFuZG9tKCkgKiA2NCB8IDBdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmVzb2x2ZShpZCk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjaGVja0F0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIGF0X2hhc2guJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVBdEhhc2gocGFyYW1zKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2hlY2tTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxhbnk+IHtcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIHNpZ25hdHVyZS4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtcyk7XG4gICAgfVxuXG5cbiAgICAvKipcbiAgICAgKiBTdGFydCB0aGUgaW1wbGljaXQgZmxvdyBvciB0aGUgY29kZSBmbG93LFxuICAgICAqIGRlcGVuZGluZyBvbiB5b3VyIGNvbmZpZ3VyYXRpb24uXG4gICAgICovXG4gICAgcHVibGljIGluaXRMb2dpbkZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICkge1xuICAgICAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmluaXRJbXBsaWNpdEZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3RhcnRzIHRoZSBhdXRob3JpemF0aW9uIGNvZGUgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICAgKiB0aGUgYXV0aCBzZXJ2ZXJzIGxvZ2luIHVybC5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdENvZGVGbG93KFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zID0ge31cbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpKVxuICAgICAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByaXZhdGUgaW5pdENvZGVGbG93SW50ZXJuYWwoXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2xvZ2luVXJsIG11c3QgdXNlIEh0dHAuIEFsc28gY2hlY2sgcHJvcGVydHkgcmVxdWlyZUh0dHBzLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsICcnLCBudWxsLCBmYWxzZSwgcGFyYW1zKVxuICAgICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk6IFByb21pc2U8W3N0cmluZywgc3RyaW5nXT4ge1xuXG4gICAgICAgIGlmICghdGhpcy5jcnlwdG8pIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignUEtDSSBzdXBwb3J0IGZvciBjb2RlIGZsb3cgbmVlZHMgYSBDcnlwdG9IYW5kZXIuIERpZCB5b3UgaW1wb3J0IHRoZSBPQXV0aE1vZHVsZSB1c2luZyBmb3JSb290KCkgPycpO1xuICAgICAgICB9XG5cblxuICAgICAgICBjb25zdCB2ZXJpZmllciA9IGF3YWl0IHRoaXMuY3JlYXRlTm9uY2UoKTtcbiAgICAgICAgY29uc3QgY2hhbGxlbmdlUmF3ID0gYXdhaXQgdGhpcy5jcnlwdG8uY2FsY0hhc2godmVyaWZpZXIsICdzaGEtMjU2Jyk7XG4gICAgICAgIGNvbnN0IGNoYWxsYW5nZSA9IGJhc2U2NFVybEVuY29kZShjaGFsbGVuZ2VSYXcpO1xuXG4gICAgICAgIHJldHVybiBbY2hhbGxhbmdlLCB2ZXJpZmllcl07XG4gICAgfVxufVxuIl19