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
export class OAuthService extends AuthConfig {
    /**
     * @param {?} ngZone
     * @param {?} http
     * @param {?} storage
     * @param {?} tokenValidationHandler
     * @param {?} config
     * @param {?} urlHelper
     * @param {?} logger
     * @param {?} crypto
     */
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto) {
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        /**
         * \@internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.debug('angular-oauth2-oidc v8-beta');
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).'
                + 'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param {?} config the configuration
     * @return {?}
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign((/** @type {?} */ ({})), new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    /**
     * @protected
     * @return {?}
     */
    configChanged() {
        this.setupRefreshTimer();
    }
    /**
     * @return {?}
     */
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    restartRefreshTimerIfStillLoggedIn() {
        this.setupExpirationTimers();
    }
    /**
     * @protected
     * @return {?}
     */
    setupSessionCheck() {
        this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'token_received'))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            this.initSessionCheck();
        }));
    }
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
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        /** @type {?} */
        let shouldRunSilentRefresh = true;
        this.events.pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
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
        e => e.type === 'token_expires'))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            /** @type {?} */
            const event = (/** @type {?} */ (e));
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) && shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch((/**
                 * @param {?} _
                 * @return {?}
                 */
                _ => {
                    this.debug('Automatic silent refresh did not work');
                }));
            }
        }));
        this.restartRefreshTimerIfStillLoggedIn();
    }
    /**
     * @protected
     * @param {?} params
     * @param {?} noPrompt
     * @return {?}
     */
    refreshInternal(params, noPrompt) {
        if (this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then((/**
         * @param {?} doc
         * @return {?}
         */
        doc => {
            return this.tryLogin(options);
        }));
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initImplicitFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        return this.loadDiscoveryDocumentAndTryLogin(options).then((/**
         * @param {?} _
         * @return {?}
         */
        _ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                this.initImplicitFlow();
                return false;
            }
            else {
                return true;
            }
        }));
    }
    /**
     * @protected
     * @param {...?} args
     * @return {?}
     */
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(console, args);
        }
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlFromDiscoveryDocument(url) {
        /** @type {?} */
        const errors = [];
        /** @type {?} */
        const httpsCheck = this.validateUrlForHttps(url);
        /** @type {?} */
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        /** @type {?} */
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    /**
     * @protected
     * @return {?}
     */
    setupRefreshTimer() {
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
        e => e.type === 'token_received'))).subscribe((/**
         * @param {?} _
         * @return {?}
         */
        _ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    setupExpirationTimers() {
        /** @type {?} */
        const idTokenExp = this.getIdTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        const accessTokenExp = this.getAccessTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        const useAccessTokenExp = accessTokenExp <= idTokenExp;
        if (this.hasValidAccessToken() && useAccessTokenExp) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken() && !useAccessTokenExp) {
            this.setupIdTokenTimer();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    setupAccessTokenTimer() {
        /** @type {?} */
        const expiration = this.getAccessTokenExpiration();
        /** @type {?} */
        const storedAt = this.getAccessTokenStoredAt();
        /** @type {?} */
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            e => {
                this.ngZone.run((/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(e);
                }));
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    setupIdTokenTimer() {
        /** @type {?} */
        const expiration = this.getIdTokenExpiration();
        /** @type {?} */
        const storedAt = this.getIdTokenStoredAt();
        /** @type {?} */
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            e => {
                this.ngZone.run((/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(e);
                }));
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    /**
     * @protected
     * @param {?} storedAt
     * @param {?} expiration
     * @return {?}
     */
    calcTimeout(storedAt, expiration) {
        /** @type {?} */
        const now = Date.now();
        /** @type {?} */
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
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
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
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
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject('issuer must use https, or config value for property requireHttps must allow http');
                return;
            }
            this.http.get(fullUrl).subscribe((/**
             * @param {?} doc
             * @return {?}
             */
            doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = doc.token_endpoint;
                this.userinfoEndpoint = doc.userinfo_endpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl = doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                jwks => {
                    /** @type {?} */
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    /** @type {?} */
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                }))
                    .catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                }));
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    loadJwks() {
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }), (/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                }));
            }
            else {
                resolve(null);
            }
        }));
    }
    /**
     * @protected
     * @param {?} doc
     * @return {?}
     */
    validateDiscoveryDocument(doc) {
        /** @type {?} */
        let errors;
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
    }
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
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then((/**
         * @return {?}
         */
        () => this.loadUserProfile()));
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     * @return {?}
     */
    loadUserProfile() {
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
        (resolve, reject) => {
            /** @type {?} */
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http.get(this.userinfoEndpoint, { headers }).subscribe((/**
             * @param {?} info
             * @return {?}
             */
            info => {
                this.debug('userinfo received', info);
                /** @type {?} */
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        /** @type {?} */
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * \@stable
             * @type {?}
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                /** @type {?} */
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     * @return {?}
     */
    refreshToken() {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            /** @type {?} */
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('client_id', this.clientId)
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            if (this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            /** @type {?} */
            const headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true))
                        .pipe(tap((/**
                     * @param {?} result
                     * @return {?}
                     */
                    result => this.storeIdToken(result))), map((/**
                     * @param {?} _
                     * @return {?}
                     */
                    _ => tokenResponse)));
                }
                else {
                    return of(tokenResponse);
                }
            })))
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
            /** @type {?} */
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                onLoginError: (/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.eventsSubject.next(new OAuthErrorEvent('silent_refresh_error', err));
                }),
                onTokenReceived: (/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(new OAuthSuccessEvent('silently_refreshed'));
                })
            }).catch((/**
             * @param {?} err
             * @return {?}
             */
            err => this.debug('tryLogin during silent refresh failed', err)));
        });
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     * @param {?=} params
     * @param {?=} noPrompt
     * @return {?}
     */
    silentRefresh(params = {}, noPrompt = true) {
        /** @type {?} */
        const claims = this.getIdentityClaims() || {};
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
        const existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        /** @type {?} */
        const iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        /** @type {?} */
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then((/**
         * @param {?} url
         * @return {?}
         */
        url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        }));
        /** @type {?} */
        const errors = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e instanceof OAuthErrorEvent)), first());
        /** @type {?} */
        const success = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'silently_refreshed')), first());
        /** @type {?} */
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e.type === 'silent_refresh_timeout') {
                this.eventsSubject.next(e);
            }
        })), map((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e instanceof OAuthErrorEvent) {
                throw e;
            }
            return e;
        })))
            .toPromise();
    }
    /**
     * @param {?=} options
     * @return {?}
     */
    initImplicitFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then((/**
         * @param {?} url
         * @return {?}
         */
        url => {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            (resolve, reject) => {
                /** @type {?} */
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                /** @type {?} */
                const cleanup = (/**
                 * @return {?}
                 */
                () => {
                    window.removeEventListener('message', listener);
                    windowRef.close();
                    windowRef = null;
                });
                /** @type {?} */
                const listener = (/**
                 * @param {?} e
                 * @return {?}
                 */
                (e) => {
                    /** @type {?} */
                    const message = this.processMessageEventMessage(e);
                    this.tryLogin({
                        customHashFragment: message,
                        preventClearHashAfterLogin: true,
                    }).then((/**
                     * @return {?}
                     */
                    () => {
                        cleanup();
                        resolve();
                    }), (/**
                     * @param {?} err
                     * @return {?}
                     */
                    err => {
                        cleanup();
                        reject(err);
                    }));
                });
                window.addEventListener('message', listener);
            }));
        }));
    }
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        /** @type {?} */
        const height = options.height || 470;
        /** @type {?} */
        const width = options.width || 500;
        /** @type {?} */
        const left = (screen.width / 2) - (width / 2);
        /** @type {?} */
        const top = (screen.height / 2) - (height / 2);
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    /**
     * @protected
     * @param {?} e
     * @return {?}
     */
    processMessageEventMessage(e) {
        /** @type {?} */
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        /** @type {?} */
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    /**
     * @protected
     * @return {?}
     */
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        /** @type {?} */
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    }
    /**
     * @protected
     * @return {?}
     */
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
            /** @type {?} */
            const origin = e.origin.toLowerCase();
            /** @type {?} */
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer);
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run((/**
                     * @return {?}
                     */
                    () => {
                        this.handleSessionChange();
                    }));
                    break;
                case 'error':
                    this.ngZone.run((/**
                     * @return {?}
                     */
                    () => {
                        this.handleSessionError();
                    }));
                    break;
            }
            this.debug('got info from session check inframe', e);
        });
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            window.addEventListener('message', this.sessionCheckEventListener);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionChange() {
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.debug('silent refresh failed after session changed')));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    /**
     * @protected
     * @return {?}
     */
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        (e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error')), first())
            .subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    /**
     * @protected
     * @return {?}
     */
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        /** @type {?} */
        const existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        /** @type {?} */
        const iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        /** @type {?} */
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    /**
     * @protected
     * @return {?}
     */
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    checkSession() {
        /** @type {?} */
        const iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        /** @type {?} */
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        /** @type {?} */
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    /**
     * @protected
     * @param {?=} state
     * @param {?=} loginHint
     * @param {?=} customRedirectUri
     * @param {?=} noPrompt
     * @param {?=} params
     * @return {?}
     */
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            /** @type {?} */
            const that = this;
            /** @type {?} */
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            /** @type {?} */
            const nonce = yield this.createAndSaveNonce();
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
            /** @type {?} */
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            /** @type {?} */
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            /** @type {?} */
            let url = that.loginUrl +
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
            if (this.responseType === 'code' && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                this._storage.setItem('PKCI_verifier', verifier);
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
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
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    /**
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use https, or config value for property requireHttps must allow http');
        }
        /** @type {?} */
        let addParams = {};
        /** @type {?} */
        let loginHint = null;
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
        error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        }));
    }
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
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            e => e.type === 'discovery_document_loaded')))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.initImplicitFlowInternal(additionalState, params)));
        }
    }
    /**
     * Reset current implicit flow
     *
     * \@description This method allows resetting the current implict flow in order to be initialized again.
     * @return {?}
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    callOnTokenReceivedIfExists(options) {
        /** @type {?} */
        const that = this;
        if (options.onTokenReceived) {
            /** @type {?} */
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    /**
     * @protected
     * @param {?} accessToken
     * @param {?} refreshToken
     * @param {?} expiresIn
     * @param {?} grantedScopes
     * @return {?}
     */
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            /** @type {?} */
            const expiresInMilliSeconds = expiresIn * 1000;
            /** @type {?} */
            const now = new Date();
            /** @type {?} */
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param {?=} options Optional options.
     * @return {?}
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow().then((/**
             * @param {?} _
             * @return {?}
             */
            _ => true));
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    /**
     * @private
     * @param {?} queryString
     * @return {?}
     */
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * @return {?}
     */
    tryLoginCodeFlow() {
        /** @type {?} */
        const parts = this.parseQueryString(window.location.search);
        /** @type {?} */
        const code = parts['code'];
        /** @type {?} */
        const state = parts['state'];
        /** @type {?} */
        const href = location.href
            .replace(/[&\?]code=[^&\$]*/, '')
            .replace(/[&\?]scope=[^&\$]*/, '')
            .replace(/[&\?]state=[^&\$]*/, '')
            .replace(/[&\?]session_state=[^&\$]*/, '');
        history.replaceState(null, window.name, href);
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            /** @type {?} */
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        /** @type {?} */
        const success = this.validateNonce(nonceInState);
        if (!success) {
            /** @type {?} */
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        if (code) {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            (resolve, reject) => {
                this.getTokenFromCode(code).then((/**
                 * @param {?} result
                 * @return {?}
                 */
                result => {
                    resolve();
                })).catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    reject(err);
                }));
            }));
        }
        else {
            return Promise.resolve();
        }
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     * @private
     * @param {?} code
     * @return {?}
     */
    getTokenFromCode(code) {
        /** @type {?} */
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', this.redirectUri);
        if (!this.disablePKCE) {
            /** @type {?} */
            const pkciVerifier = this._storage.getItem('PKCI_verifier');
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    }
    /**
     * @private
     * @param {?} params
     * @return {?}
     */
    fetchAndProcessToken(params) {
        /** @type {?} */
        let headers = new HttpHeaders()
            .set('Content-Type', 'application/x-www-form-urlencoded');
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use Http. Also check property requireHttps.');
        }
        if (this.useHttpBasicAuth) {
            /** @type {?} */
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
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
        (resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http.post(this.tokenEndpoint, params, { headers }).subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            (tokenResponse) => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then((/**
                     * @param {?} result
                     * @return {?}
                     */
                    result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    }))
                        .catch((/**
                     * @param {?} reason
                     * @return {?}
                     */
                    reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    }));
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }), (/**
             * @param {?} err
             * @return {?}
             */
            (err) => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param {?=} options Optional options.
     * @return {?}
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        /** @type {?} */
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        /** @type {?} */
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            /** @type {?} */
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        const accessToken = parts['access_token'];
        /** @type {?} */
        const idToken = parts['id_token'];
        /** @type {?} */
        const sessionState = parts['session_state'];
        /** @type {?} */
        const grantedScopes = parts['scope'];
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
            const success = this.validateNonce(nonceInState);
            if (!success) {
                /** @type {?} */
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
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
        result => {
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
                _ => result));
            }
            return result;
        }))
            .then((/**
         * @param {?} result
         * @return {?}
         */
        result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        }))
            .catch((/**
         * @param {?} reason
         * @return {?}
         */
        reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        }));
    }
    /**
     * @private
     * @param {?} state
     * @return {?}
     */
    parseState(state) {
        /** @type {?} */
        let nonce = state;
        /** @type {?} */
        let userState = '';
        if (state) {
            /** @type {?} */
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    /**
     * @protected
     * @param {?} nonceInState
     * @return {?}
     */
    validateNonce(nonceInState) {
        /** @type {?} */
        const savedNonce = this._storage.getItem('nonce');
        if (savedNonce !== nonceInState) {
            /** @type {?} */
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    /**
     * @protected
     * @param {?} idToken
     * @return {?}
     */
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    /**
     * @protected
     * @param {?} sessionState
     * @return {?}
     */
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    /**
     * @protected
     * @return {?}
     */
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    /**
     * @protected
     * @param {?} options
     * @param {?} parts
     * @return {?}
     */
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     * @param {?} idToken
     * @param {?} accessToken
     * @param {?=} skipNonceCheck
     * @return {?}
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        /** @type {?} */
        const tokenParts = idToken.split('.');
        /** @type {?} */
        const headerBase64 = this.padBase64(tokenParts[0]);
        /** @type {?} */
        const headerJson = b64DecodeUnicode(headerBase64);
        /** @type {?} */
        const header = JSON.parse(headerJson);
        /** @type {?} */
        const claimsBase64 = this.padBase64(tokenParts[1]);
        /** @type {?} */
        const claimsJson = b64DecodeUnicode(claimsBase64);
        /** @type {?} */
        const claims = JSON.parse(claimsJson);
        /** @type {?} */
        const savedNonce = this._storage.getItem('nonce');
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every((/**
             * @param {?} v
             * @return {?}
             */
            v => v !== this.clientId))) {
                /** @type {?} */
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                /** @type {?} */
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            /** @type {?} */
            const err = 'No sub claim in id_token';
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
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            /** @type {?} */
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            /** @type {?} */
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            /** @type {?} */
            const err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            /** @type {?} */
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        const now = Date.now();
        /** @type {?} */
        const issuedAtMSec = claims.iat * 1000;
        /** @type {?} */
        const expiresAtMSec = claims.exp * 1000;
        /** @type {?} */
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            /** @type {?} */
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        /** @type {?} */
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: (/**
             * @return {?}
             */
            () => this.loadJwks())
        };
        return this.checkAtHash(validationParams)
            .then((/**
         * @param {?} atHashValid
         * @return {?}
         */
        atHashValid => {
            if (!this.disableAtHashCheck &&
                this.requestAccessToken &&
                !atHashValid) {
                /** @type {?} */
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then((/**
             * @param {?} _
             * @return {?}
             */
            _ => {
                /** @type {?} */
                const result = {
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
    }
    /**
     * Returns the received claims about the user.
     * @return {?}
     */
    getIdentityClaims() {
        /** @type {?} */
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     * @return {?}
     */
    getGrantedScopes() {
        /** @type {?} */
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     * @return {?}
     */
    getIdToken() {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    }
    /**
     * @protected
     * @param {?} base64data
     * @return {?}
     */
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     * @return {?}
     */
    getAccessToken() {
        return this._storage
            ? this._storage.getItem('access_token')
            : null;
    }
    /**
     * @return {?}
     */
    getRefreshToken() {
        return this._storage
            ? this._storage.getItem('refresh_token')
            : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     * @return {?}
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    /**
     * @protected
     * @return {?}
     */
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    /**
     * @protected
     * @return {?}
     */
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     * @return {?}
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Checkes, whether there is a valid access_token.
     * @return {?}
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            /** @type {?} */
            const expiresAt = this._storage.getItem('expires_at');
            /** @type {?} */
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     * @return {?}
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            /** @type {?} */
            const expiresAt = this._storage.getItem('id_token_expires_at');
            /** @type {?} */
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     * @return {?}
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param {?=} noRedirectToLogoutUrl
     * @return {?}
     */
    logOut(noRedirectToLogoutUrl = false) {
        /** @type {?} */
        const id_token = this.getIdToken();
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
        let logoutUrl;
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
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            /** @type {?} */
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    }
    /**
     * @ignore
     * @return {?}
     */
    createAndSaveNonce() {
        /** @type {?} */
        const that = this;
        return this.createNonce().then((/**
         * @param {?} nonce
         * @return {?}
         */
        function (nonce) {
            that._storage.setItem('nonce', nonce);
            return nonce;
        }));
    }
    /**
     * @ignore
     * @return {?}
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    }
    /**
     * @protected
     * @return {?}
     */
    createNonce() {
        return new Promise((/**
         * @param {?} resolve
         * @return {?}
         */
        (resolve) => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
                         * This alphabet uses a-z A-Z 0-9 _- symbols.
                         * Symbols order was changed for better gzip compression.
                         */
            /** @type {?} */
            const url = 'Uint8ArdomValuesObj012345679BCDEFGHIJKLMNPQRSTWXYZ_cfghkpqvwxyz-';
            /** @type {?} */
            let size = 45;
            /** @type {?} */
            let id = '';
            /** @type {?} */
            const crypto = self.crypto || self['msCrypto'];
            if (crypto) {
                /** @type {?} */
                const bytes = crypto.getRandomValues(new Uint8Array(size));
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
    }
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    checkAtHash(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events.pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            e => e.type === 'discovery_document_loaded')))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.initCodeFlowInternal(additionalState, params)));
        }
    }
    /**
     * @private
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use Http. Also check property requireHttps.');
        }
        this.createLoginUrl(additionalState, '', null, false, params).then(this.config.openUri).catch((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    createChallangeVerifierPairForPKCE() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCI support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            /** @type {?} */
            const verifier = yield this.createNonce();
            /** @type {?} */
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            /** @type {?} */
            const challange = base64UrlEncode(challengeRaw);
            return [challange, verifier];
        });
    }
}
OAuthService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: CryptoHandler, decorators: [{ type: Optional }] }
];
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFhLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBRTNFLE9BQU8sRUFDSCxpQkFBaUIsRUFFcEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUgsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDcEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNILFdBQVcsRUFDWCxZQUFZLEVBTWYsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3BELE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSxtQ0FBbUMsQ0FBQzs7Ozs7O0FBUWxFLE1BQU0sT0FBTyxZQUFhLFNBQVEsVUFBVTs7Ozs7Ozs7Ozs7SUErQ3hDLFlBQ2MsTUFBYyxFQUNkLElBQWdCLEVBQ2QsT0FBcUIsRUFDckIsc0JBQXlDLEVBQy9CLE1BQWtCLEVBQzlCLFNBQTJCLEVBQzNCLE1BQW1CLEVBQ1AsTUFBcUI7UUFFM0MsS0FBSyxFQUFFLENBQUM7UUFURSxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ2QsU0FBSSxHQUFKLElBQUksQ0FBWTtRQUdKLFdBQU0sR0FBTixNQUFNLENBQVk7UUFDOUIsY0FBUyxHQUFULFNBQVMsQ0FBa0I7UUFDM0IsV0FBTSxHQUFOLE1BQU0sQ0FBYTtRQUNQLFdBQU0sR0FBTixNQUFNLENBQWU7Ozs7O1FBekN4Qyw0QkFBdUIsR0FBRyxLQUFLLENBQUM7Ozs7O1FBa0JoQyxVQUFLLEdBQUksRUFBRSxDQUFDO1FBRVQsa0JBQWEsR0FBd0IsSUFBSSxPQUFPLEVBQWMsQ0FBQztRQUMvRCxtQ0FBOEIsR0FBb0IsSUFBSSxPQUFPLEVBQVUsQ0FBQztRQUV4RSx3QkFBbUIsR0FBa0IsRUFBRSxDQUFDO1FBUXhDLG1CQUFjLEdBQUcsS0FBSyxDQUFDO1FBYzdCLElBQUksQ0FBQyxLQUFLLENBQUMsNkJBQTZCLENBQUMsQ0FBQztRQUUxQyxJQUFJLENBQUMsd0JBQXdCLEdBQUcsSUFBSSxDQUFDLDhCQUE4QixDQUFDLFlBQVksRUFBRSxDQUFDO1FBQ25GLElBQUksQ0FBQyxNQUFNLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQyxZQUFZLEVBQUUsQ0FBQztRQUVoRCxJQUFJLHNCQUFzQixFQUFFO1lBQ3hCLElBQUksQ0FBQyxzQkFBc0IsR0FBRyxzQkFBc0IsQ0FBQztTQUN4RDtRQUVELElBQUksTUFBTSxFQUFFO1lBQ1IsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQztTQUMxQjtRQUVELElBQUk7WUFDQSxJQUFJLE9BQU8sRUFBRTtnQkFDVCxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFDO2FBQzVCO2lCQUFNLElBQUksT0FBTyxjQUFjLEtBQUssV0FBVyxFQUFFO2dCQUM5QyxJQUFJLENBQUMsVUFBVSxDQUFDLGNBQWMsQ0FBQyxDQUFDO2FBQ25DO1NBQ0o7UUFBQyxPQUFPLENBQUMsRUFBRTtZQUVSLE9BQU8sQ0FBQyxLQUFLLENBQ1Qsc0VBQXNFO2tCQUNwRSx5RUFBeUUsRUFDM0UsQ0FBQyxDQUNKLENBQUM7U0FDTDtRQUVELElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO0lBQzdCLENBQUM7Ozs7OztJQU1NLFNBQVMsQ0FBQyxNQUFrQjtRQUMvQiw4Q0FBOEM7UUFDOUMsNkJBQTZCO1FBQzdCLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLElBQUksVUFBVSxFQUFFLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFOUMsSUFBSSxDQUFDLE1BQU0sR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDLG1CQUFBLEVBQUUsRUFBYyxFQUFFLElBQUksVUFBVSxFQUFFLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFeEUsSUFBSSxJQUFJLENBQUMsb0JBQW9CLEVBQUU7WUFDM0IsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7U0FDNUI7UUFFRCxJQUFJLENBQUMsYUFBYSxFQUFFLENBQUM7SUFDekIsQ0FBQzs7Ozs7SUFFUyxhQUFhO1FBQ25CLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO0lBQzdCLENBQUM7Ozs7SUFFTSxtQ0FBbUM7UUFDdEMsSUFBSSxJQUFJLENBQUMsZUFBZSxFQUFFLEVBQUU7WUFDeEIsSUFBSSxDQUFDLGdCQUFnQixFQUFFLENBQUM7U0FDM0I7SUFDTCxDQUFDOzs7OztJQUVTLGtDQUFrQztRQUN4QyxJQUFJLENBQUMscUJBQXFCLEVBQUUsQ0FBQztJQUNqQyxDQUFDOzs7OztJQUVTLGlCQUFpQjtRQUN2QixJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixFQUFDLENBQUMsQ0FBQyxTQUFTOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDckUsSUFBSSxDQUFDLGdCQUFnQixFQUFFLENBQUM7UUFDNUIsQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7Ozs7Ozs7OztJQVVNLDJCQUEyQixDQUFDLFNBQWlCLEVBQUUsRUFBRSxRQUE4QyxFQUFFLFFBQVEsR0FBRyxJQUFJOztZQUNqSCxzQkFBc0IsR0FBRyxJQUFJO1FBQ2pDLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUNkLEdBQUc7Ozs7UUFBQyxDQUFDLENBQUMsRUFBRSxFQUFFO1lBQ1IsSUFBSSxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixFQUFFO2dCQUMvQixzQkFBc0IsR0FBRyxJQUFJLENBQUM7YUFDL0I7aUJBQU0sSUFBSSxDQUFDLENBQUMsSUFBSSxLQUFLLFFBQVEsRUFBRTtnQkFDOUIsc0JBQXNCLEdBQUcsS0FBSyxDQUFDO2FBQ2hDO1FBQ0gsQ0FBQyxFQUFDLEVBQ0YsTUFBTTs7OztRQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxlQUFlLEVBQUMsQ0FDeEMsQ0FBQyxTQUFTOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUU7O2tCQUNSLEtBQUssR0FBRyxtQkFBQSxDQUFDLEVBQWtCO1lBQ2pDLElBQUksQ0FBQyxRQUFRLElBQUksSUFBSSxJQUFJLFFBQVEsS0FBSyxLQUFLLElBQUksS0FBSyxDQUFDLElBQUksS0FBSyxRQUFRLENBQUMsSUFBSSxzQkFBc0IsRUFBRTtnQkFDakcsb0RBQW9EO2dCQUNwRCxJQUFJLENBQUMsZUFBZSxDQUFDLE1BQU0sRUFBRSxRQUFRLENBQUMsQ0FBQyxLQUFLOzs7O2dCQUFDLENBQUMsQ0FBQyxFQUFFO29CQUMvQyxJQUFJLENBQUMsS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUM7Z0JBQ3RELENBQUMsRUFBQyxDQUFDO2FBQ0o7UUFDSCxDQUFDLEVBQUMsQ0FBQztRQUVILElBQUksQ0FBQyxrQ0FBa0MsRUFBRSxDQUFDO0lBQzVDLENBQUM7Ozs7Ozs7SUFFUyxlQUFlLENBQUMsTUFBTSxFQUFFLFFBQVE7UUFDdEMsSUFBSSxJQUFJLENBQUMsWUFBWSxLQUFLLE1BQU0sRUFBRTtZQUM5QixPQUFPLElBQUksQ0FBQyxZQUFZLEVBQUUsQ0FBQztTQUM5QjthQUFNO1lBQ0gsT0FBTyxJQUFJLENBQUMsYUFBYSxDQUFDLE1BQU0sRUFBRSxRQUFRLENBQUMsQ0FBQztTQUMvQztJQUNMLENBQUM7Ozs7Ozs7OztJQVNNLGdDQUFnQyxDQUFDLFVBQXdCLElBQUk7UUFDaEUsT0FBTyxJQUFJLENBQUMscUJBQXFCLEVBQUUsQ0FBQyxJQUFJOzs7O1FBQUMsR0FBRyxDQUFDLEVBQUU7WUFDM0MsT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ2xDLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7Ozs7O0lBU00sNkJBQTZCLENBQUMsVUFBd0IsSUFBSTtRQUM3RCxPQUFPLElBQUksQ0FBQyxnQ0FBZ0MsQ0FBQyxPQUFPLENBQUMsQ0FBQyxJQUFJOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDM0QsSUFBSSxDQUFDLElBQUksQ0FBQyxlQUFlLEVBQUUsSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsRUFBRSxFQUFFO2dCQUN4RCxJQUFJLENBQUMsZ0JBQWdCLEVBQUUsQ0FBQztnQkFDeEIsT0FBTyxLQUFLLENBQUM7YUFDaEI7aUJBQU07Z0JBQ0gsT0FBTyxJQUFJLENBQUM7YUFDZjtRQUNMLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7O0lBRVMsS0FBSyxDQUFDLEdBQUcsSUFBSTtRQUNuQixJQUFJLElBQUksQ0FBQyxvQkFBb0IsRUFBRTtZQUMzQixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQyxDQUFDO1NBQzFDO0lBQ0wsQ0FBQzs7Ozs7O0lBRVMsZ0NBQWdDLENBQUMsR0FBVzs7Y0FDNUMsTUFBTSxHQUFhLEVBQUU7O2NBQ3JCLFVBQVUsR0FBRyxJQUFJLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDOztjQUMxQyxXQUFXLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixDQUFDLEdBQUcsQ0FBQztRQUV0RCxJQUFJLENBQUMsVUFBVSxFQUFFO1lBQ2IsTUFBTSxDQUFDLElBQUksQ0FDUCxtRUFBbUUsQ0FDdEUsQ0FBQztTQUNMO1FBRUQsSUFBSSxDQUFDLFdBQVcsRUFBRTtZQUNkLE1BQU0sQ0FBQyxJQUFJLENBQ1AsbUVBQW1FO2dCQUNuRSxzREFBc0QsQ0FDekQsQ0FBQztTQUNMO1FBRUQsT0FBTyxNQUFNLENBQUM7SUFDbEIsQ0FBQzs7Ozs7O0lBRVMsbUJBQW1CLENBQUMsR0FBVztRQUNyQyxJQUFJLENBQUMsR0FBRyxFQUFFO1lBQ04sT0FBTyxJQUFJLENBQUM7U0FDZjs7Y0FFSyxLQUFLLEdBQUcsR0FBRyxDQUFDLFdBQVcsRUFBRTtRQUUvQixJQUFJLElBQUksQ0FBQyxZQUFZLEtBQUssS0FBSyxFQUFFO1lBQzdCLE9BQU8sSUFBSSxDQUFDO1NBQ2Y7UUFFRCxJQUNJLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyw4QkFBOEIsQ0FBQztZQUN4QyxLQUFLLENBQUMsS0FBSyxDQUFDLDhCQUE4QixDQUFDLENBQUM7WUFDaEQsSUFBSSxDQUFDLFlBQVksS0FBSyxZQUFZLEVBQ3BDO1lBQ0UsT0FBTyxJQUFJLENBQUM7U0FDZjtRQUVELE9BQU8sS0FBSyxDQUFDLFVBQVUsQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN4QyxDQUFDOzs7Ozs7SUFFUyx3QkFBd0IsQ0FBQyxHQUFXO1FBQzFDLElBQUksQ0FBQyxJQUFJLENBQUMsaUNBQWlDLEVBQUU7WUFDekMsT0FBTyxJQUFJLENBQUM7U0FDZjtRQUNELElBQUksQ0FBQyxHQUFHLEVBQUU7WUFDTixPQUFPLElBQUksQ0FBQztTQUNmO1FBQ0QsT0FBTyxHQUFHLENBQUMsV0FBVyxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLENBQUMsQ0FBQztJQUNuRSxDQUFDOzs7OztJQUVTLGlCQUFpQjtRQUN2QixJQUFJLE9BQU8sTUFBTSxLQUFLLFdBQVcsRUFBRTtZQUMvQixJQUFJLENBQUMsS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUM7WUFDcEQsT0FBTztTQUNWO1FBRUQsSUFBSSxJQUFJLENBQUMsZUFBZSxFQUFFLEVBQUU7WUFDeEIsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7WUFDN0IsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7WUFDekIsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7U0FDaEM7UUFFRCxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixFQUFDLENBQUMsQ0FBQyxTQUFTOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDckUsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7WUFDN0IsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7WUFDekIsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7UUFDakMsQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7OztJQUVTLHFCQUFxQjs7Y0FDckIsVUFBVSxHQUFHLElBQUksQ0FBQyxvQkFBb0IsRUFBRSxJQUFJLE1BQU0sQ0FBQyxTQUFTOztjQUM1RCxjQUFjLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixFQUFFLElBQUksTUFBTSxDQUFDLFNBQVM7O2NBQ3BFLGlCQUFpQixHQUFHLGNBQWMsSUFBSSxVQUFVO1FBRXRELElBQUksSUFBSSxDQUFDLG1CQUFtQixFQUFFLElBQUksaUJBQWlCLEVBQUU7WUFDakQsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7U0FDaEM7UUFFRCxJQUFJLElBQUksQ0FBQyxlQUFlLEVBQUUsSUFBSSxDQUFDLGlCQUFpQixFQUFFO1lBQzlDLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO1NBQzVCO0lBQ0wsQ0FBQzs7Ozs7SUFFUyxxQkFBcUI7O2NBQ3JCLFVBQVUsR0FBRyxJQUFJLENBQUMsd0JBQXdCLEVBQUU7O2NBQzVDLFFBQVEsR0FBRyxJQUFJLENBQUMsc0JBQXNCLEVBQUU7O2NBQ3hDLE9BQU8sR0FBRyxJQUFJLENBQUMsV0FBVyxDQUFDLFFBQVEsRUFBRSxVQUFVLENBQUM7UUFFdEQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUI7OztRQUFDLEdBQUcsRUFBRTtZQUMvQixJQUFJLENBQUMsOEJBQThCLEdBQUcsRUFBRSxDQUNwQyxJQUFJLGNBQWMsQ0FBQyxlQUFlLEVBQUUsY0FBYyxDQUFDLENBQ3REO2lCQUNJLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUM7aUJBQ3BCLFNBQVM7Ozs7WUFBQyxDQUFDLENBQUMsRUFBRTtnQkFDWCxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUc7OztnQkFBQyxHQUFHLEVBQUU7b0JBQ2pCLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMvQixDQUFDLEVBQUMsQ0FBQztZQUNQLENBQUMsRUFBQyxDQUFDO1FBQ1gsQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7OztJQUVTLGlCQUFpQjs7Y0FDakIsVUFBVSxHQUFHLElBQUksQ0FBQyxvQkFBb0IsRUFBRTs7Y0FDeEMsUUFBUSxHQUFHLElBQUksQ0FBQyxrQkFBa0IsRUFBRTs7Y0FDcEMsT0FBTyxHQUFHLElBQUksQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFLFVBQVUsQ0FBQztRQUV0RCxJQUFJLENBQUMsTUFBTSxDQUFDLGlCQUFpQjs7O1FBQUMsR0FBRyxFQUFFO1lBQy9CLElBQUksQ0FBQywwQkFBMEIsR0FBRyxFQUFFLENBQ2hDLElBQUksY0FBYyxDQUFDLGVBQWUsRUFBRSxVQUFVLENBQUMsQ0FDbEQ7aUJBQ0ksSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztpQkFDcEIsU0FBUzs7OztZQUFDLENBQUMsQ0FBQyxFQUFFO2dCQUNYLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRzs7O2dCQUFDLEdBQUcsRUFBRTtvQkFDakIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQy9CLENBQUMsRUFBQyxDQUFDO1lBQ1AsQ0FBQyxFQUFDLENBQUM7UUFDWCxDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7O0lBRVMscUJBQXFCO1FBQzNCLElBQUksSUFBSSxDQUFDLDhCQUE4QixFQUFFO1lBQ3JDLElBQUksQ0FBQyw4QkFBOEIsQ0FBQyxXQUFXLEVBQUUsQ0FBQztTQUNyRDtJQUNMLENBQUM7Ozs7O0lBRVMsaUJBQWlCO1FBQ3ZCLElBQUksSUFBSSxDQUFDLDBCQUEwQixFQUFFO1lBQ2pDLElBQUksQ0FBQywwQkFBMEIsQ0FBQyxXQUFXLEVBQUUsQ0FBQztTQUNqRDtJQUNMLENBQUM7Ozs7Ozs7SUFFUyxXQUFXLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjs7Y0FDaEQsR0FBRyxHQUFHLElBQUksQ0FBQyxHQUFHLEVBQUU7O2NBQ2hCLEtBQUssR0FBRyxDQUFDLFVBQVUsR0FBRyxRQUFRLENBQUMsR0FBRyxJQUFJLENBQUMsYUFBYSxHQUFHLENBQUMsR0FBRyxHQUFHLFFBQVEsQ0FBQztRQUM3RSxPQUFPLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEtBQUssQ0FBQyxDQUFDO0lBQzlCLENBQUM7Ozs7Ozs7Ozs7Ozs7O0lBY00sVUFBVSxDQUFDLE9BQXFCO1FBQ25DLElBQUksQ0FBQyxRQUFRLEdBQUcsT0FBTyxDQUFDO1FBQ3hCLElBQUksQ0FBQyxhQUFhLEVBQUUsQ0FBQztJQUN6QixDQUFDOzs7Ozs7Ozs7OztJQVdNLHFCQUFxQixDQUFDLFVBQWtCLElBQUk7UUFDL0MsT0FBTyxJQUFJLE9BQU87Ozs7O1FBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7WUFDbkMsSUFBSSxDQUFDLE9BQU8sRUFBRTtnQkFDVixPQUFPLEdBQUcsSUFBSSxDQUFDLE1BQU0sSUFBSSxFQUFFLENBQUM7Z0JBQzVCLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxFQUFFO29CQUN4QixPQUFPLElBQUksR0FBRyxDQUFDO2lCQUNsQjtnQkFDRCxPQUFPLElBQUksa0NBQWtDLENBQUM7YUFDakQ7WUFFRCxJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLE9BQU8sQ0FBQyxFQUFFO2dCQUNwQyxNQUFNLENBQUMsa0ZBQWtGLENBQUMsQ0FBQztnQkFDM0YsT0FBTzthQUNWO1lBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQW1CLE9BQU8sQ0FBQyxDQUFDLFNBQVM7Ozs7WUFDOUMsR0FBRyxDQUFDLEVBQUU7Z0JBQ0YsSUFBSSxDQUFDLElBQUksQ0FBQyx5QkFBeUIsQ0FBQyxHQUFHLENBQUMsRUFBRTtvQkFDdEMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQ25CLElBQUksZUFBZSxDQUFDLHFDQUFxQyxFQUFFLElBQUksQ0FBQyxDQUNuRSxDQUFDO29CQUNGLE1BQU0sQ0FBQyxxQ0FBcUMsQ0FBQyxDQUFDO29CQUM5QyxPQUFPO2lCQUNWO2dCQUVELElBQUksQ0FBQyxRQUFRLEdBQUcsR0FBRyxDQUFDLHNCQUFzQixDQUFDO2dCQUMzQyxJQUFJLENBQUMsU0FBUyxHQUFHLEdBQUcsQ0FBQyxvQkFBb0IsSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDO2dCQUM1RCxJQUFJLENBQUMsbUJBQW1CLEdBQUcsR0FBRyxDQUFDLHFCQUFxQixDQUFDO2dCQUNyRCxJQUFJLENBQUMsTUFBTSxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUM7Z0JBQ3pCLElBQUksQ0FBQyxhQUFhLEdBQUcsR0FBRyxDQUFDLGNBQWMsQ0FBQztnQkFDeEMsSUFBSSxDQUFDLGdCQUFnQixHQUFHLEdBQUcsQ0FBQyxpQkFBaUIsQ0FBQztnQkFDOUMsSUFBSSxDQUFDLE9BQU8sR0FBRyxHQUFHLENBQUMsUUFBUSxDQUFDO2dCQUM1QixJQUFJLENBQUMscUJBQXFCLEdBQUcsR0FBRyxDQUFDLG9CQUFvQixJQUFJLElBQUksQ0FBQyxxQkFBcUIsQ0FBQztnQkFFcEYsSUFBSSxDQUFDLHVCQUF1QixHQUFHLElBQUksQ0FBQztnQkFDcEMsSUFBSSxDQUFDLDhCQUE4QixDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFFOUMsSUFBSSxJQUFJLENBQUMsb0JBQW9CLEVBQUU7b0JBQzNCLElBQUksQ0FBQyxtQ0FBbUMsRUFBRSxDQUFDO2lCQUM5QztnQkFFRCxJQUFJLENBQUMsUUFBUSxFQUFFO3FCQUNWLElBQUk7Ozs7Z0JBQUMsSUFBSSxDQUFDLEVBQUU7OzBCQUNILE1BQU0sR0FBVzt3QkFDbkIsaUJBQWlCLEVBQUUsR0FBRzt3QkFDdEIsSUFBSSxFQUFFLElBQUk7cUJBQ2I7OzBCQUVLLEtBQUssR0FBRyxJQUFJLGlCQUFpQixDQUMvQiwyQkFBMkIsRUFDM0IsTUFBTSxDQUNUO29CQUNELElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO29CQUMvQixPQUFPLENBQUMsS0FBSyxDQUFDLENBQUM7b0JBQ2YsT0FBTztnQkFDWCxDQUFDLEVBQUM7cUJBQ0QsS0FBSzs7OztnQkFBQyxHQUFHLENBQUMsRUFBRTtvQkFDVCxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FDbkIsSUFBSSxlQUFlLENBQUMsK0JBQStCLEVBQUUsR0FBRyxDQUFDLENBQzVELENBQUM7b0JBQ0YsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO29CQUNaLE9BQU87Z0JBQ1gsQ0FBQyxFQUFDLENBQUM7WUFDWCxDQUFDOzs7O1lBQ0QsR0FBRyxDQUFDLEVBQUU7Z0JBQ0YsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLEVBQUUsR0FBRyxDQUFDLENBQUM7Z0JBQzNELElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNuQixJQUFJLGVBQWUsQ0FBQywrQkFBK0IsRUFBRSxHQUFHLENBQUMsQ0FDNUQsQ0FBQztnQkFDRixNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7WUFDaEIsQ0FBQyxFQUNKLENBQUM7UUFDTixDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7O0lBRVMsUUFBUTtRQUNkLE9BQU8sSUFBSSxPQUFPOzs7OztRQUFTLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFO1lBQzNDLElBQUksSUFBSSxDQUFDLE9BQU8sRUFBRTtnQkFDZCxJQUFJLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsU0FBUzs7OztnQkFDakMsSUFBSSxDQUFDLEVBQUU7b0JBQ0gsSUFBSSxDQUFDLElBQUksR0FBRyxJQUFJLENBQUM7b0JBQ2pCLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNuQixJQUFJLGlCQUFpQixDQUFDLDJCQUEyQixDQUFDLENBQ3JELENBQUM7b0JBQ0YsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO2dCQUNsQixDQUFDOzs7O2dCQUNELEdBQUcsQ0FBQyxFQUFFO29CQUNGLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLG9CQUFvQixFQUFFLEdBQUcsQ0FBQyxDQUFDO29CQUM3QyxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FDbkIsSUFBSSxlQUFlLENBQUMsaUJBQWlCLEVBQUUsR0FBRyxDQUFDLENBQzlDLENBQUM7b0JBQ0YsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUNoQixDQUFDLEVBQ0osQ0FBQzthQUNMO2lCQUFNO2dCQUNILE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQzthQUNqQjtRQUNMLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7O0lBRVMseUJBQXlCLENBQUMsR0FBcUI7O1lBQ2pELE1BQWdCO1FBRXBCLElBQUksQ0FBQyxJQUFJLENBQUMsZUFBZSxJQUFJLEdBQUcsQ0FBQyxNQUFNLEtBQUssSUFBSSxDQUFDLE1BQU0sRUFBRTtZQUNyRCxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FDYixzQ0FBc0MsRUFDdEMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLEVBQzFCLFdBQVcsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUMzQixDQUFDO1lBQ0YsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFFRCxNQUFNLEdBQUcsSUFBSSxDQUFDLGdDQUFnQyxDQUFDLEdBQUcsQ0FBQyxzQkFBc0IsQ0FBQyxDQUFDO1FBQzNFLElBQUksTUFBTSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUU7WUFDbkIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQ2IsK0RBQStELEVBQy9ELE1BQU0sQ0FDVCxDQUFDO1lBQ0YsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFFRCxNQUFNLEdBQUcsSUFBSSxDQUFDLGdDQUFnQyxDQUFDLEdBQUcsQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO1FBQ3pFLElBQUksTUFBTSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUU7WUFDbkIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQ2IsNkRBQTZELEVBQzdELE1BQU0sQ0FDVCxDQUFDO1lBQ0YsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFFRCxNQUFNLEdBQUcsSUFBSSxDQUFDLGdDQUFnQyxDQUFDLEdBQUcsQ0FBQyxjQUFjLENBQUMsQ0FBQztRQUNuRSxJQUFJLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFFO1lBQ25CLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUNiLHVEQUF1RCxFQUN2RCxNQUFNLENBQ1QsQ0FBQztTQUNMO1FBRUQsTUFBTSxHQUFHLElBQUksQ0FBQyxnQ0FBZ0MsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLENBQUMsQ0FBQztRQUN0RSxJQUFJLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFFO1lBQ25CLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUNiLDBEQUEwRCxFQUMxRCxNQUFNLENBQ1QsQ0FBQztZQUNGLE9BQU8sS0FBSyxDQUFDO1NBQ2hCO1FBRUQsTUFBTSxHQUFHLElBQUksQ0FBQyxnQ0FBZ0MsQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLENBQUM7UUFDN0QsSUFBSSxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtZQUNuQixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxpREFBaUQsRUFBRSxNQUFNLENBQUMsQ0FBQztZQUM3RSxPQUFPLEtBQUssQ0FBQztTQUNoQjtRQUVELElBQUksSUFBSSxDQUFDLG9CQUFvQixJQUFJLENBQUMsR0FBRyxDQUFDLG9CQUFvQixFQUFFO1lBQ3hELElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUNaLDBEQUEwRDtnQkFDMUQsZ0RBQWdELENBQ25ELENBQUM7U0FDTDtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2hCLENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7SUFnQk0sNkNBQTZDLENBQ2hELFFBQWdCLEVBQ2hCLFFBQWdCLEVBQ2hCLFVBQXVCLElBQUksV0FBVyxFQUFFO1FBRXhDLE9BQU8sSUFBSSxDQUFDLDJCQUEyQixDQUFDLFFBQVEsRUFBRSxRQUFRLEVBQUUsT0FBTyxDQUFDLENBQUMsSUFBSTs7O1FBQ3JFLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxlQUFlLEVBQUUsRUFDL0IsQ0FBQztJQUNOLENBQUM7Ozs7Ozs7O0lBUU0sZUFBZTtRQUNsQixJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixFQUFFLEVBQUU7WUFDN0IsTUFBTSxJQUFJLEtBQUssQ0FBQyxnREFBZ0QsQ0FBQyxDQUFDO1NBQ3JFO1FBQ0QsSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsRUFBRTtZQUNsRCxNQUFNLElBQUksS0FBSyxDQUNYLDRGQUE0RixDQUMvRixDQUFDO1NBQ0w7UUFFRCxPQUFPLElBQUksT0FBTzs7Ozs7UUFBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQUUsRUFBRTs7a0JBQzdCLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDLEdBQUcsQ0FDakMsZUFBZSxFQUNmLFNBQVMsR0FBRyxJQUFJLENBQUMsY0FBYyxFQUFFLENBQ3BDO1lBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQVcsSUFBSSxDQUFDLGdCQUFnQixFQUFFLEVBQUUsT0FBTyxFQUFFLENBQUMsQ0FBQyxTQUFTOzs7O1lBQ2pFLElBQUksQ0FBQyxFQUFFO2dCQUNILElBQUksQ0FBQyxLQUFLLENBQUMsbUJBQW1CLEVBQUUsSUFBSSxDQUFDLENBQUM7O3NCQUVoQyxjQUFjLEdBQUcsSUFBSSxDQUFDLGlCQUFpQixFQUFFLElBQUksRUFBRTtnQkFFckQsSUFBSSxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsRUFBRTtvQkFDeEIsSUFDSSxJQUFJLENBQUMsSUFBSTt3QkFDVCxDQUFDLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxJQUFJLElBQUksQ0FBQyxHQUFHLEtBQUssY0FBYyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQ2hFOzs4QkFDUSxHQUFHLEdBQ0wsNkVBQTZFOzRCQUM3RSw2Q0FBNkM7NEJBQzdDLDJFQUEyRTt3QkFFL0UsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO3dCQUNaLE9BQU87cUJBQ1Y7aUJBQ0o7Z0JBRUQsSUFBSSxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsRUFBRSxFQUFFLGNBQWMsRUFBRSxJQUFJLENBQUMsQ0FBQztnQkFFL0MsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO2dCQUNuRSxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLHFCQUFxQixDQUFDLENBQUMsQ0FBQztnQkFDdEUsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQ2xCLENBQUM7Ozs7WUFDRCxHQUFHLENBQUMsRUFBRTtnQkFDRixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyx5QkFBeUIsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDbEQsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQ25CLElBQUksZUFBZSxDQUFDLHlCQUF5QixFQUFFLEdBQUcsQ0FBQyxDQUN0RCxDQUFDO2dCQUNGLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNoQixDQUFDLEVBQ0osQ0FBQztRQUNOLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7Ozs7SUFRTSwyQkFBMkIsQ0FDOUIsUUFBZ0IsRUFDaEIsUUFBZ0IsRUFDaEIsVUFBdUIsSUFBSSxXQUFXLEVBQUU7UUFFeEMsSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsYUFBYSxDQUFDLEVBQUU7WUFDL0MsTUFBTSxJQUFJLEtBQUssQ0FDWCx5RkFBeUYsQ0FDNUYsQ0FBQztTQUNMO1FBRUQsT0FBTyxJQUFJLE9BQU87Ozs7O1FBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7Ozs7Ozs7O2dCQU8vQixNQUFNLEdBQUcsSUFBSSxVQUFVLENBQUMsRUFBRSxPQUFPLEVBQUUsSUFBSSx1QkFBdUIsRUFBRSxFQUFFLENBQUM7aUJBQ2xFLEdBQUcsQ0FBQyxZQUFZLEVBQUUsVUFBVSxDQUFDO2lCQUM3QixHQUFHLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQyxLQUFLLENBQUM7aUJBQ3hCLEdBQUcsQ0FBQyxVQUFVLEVBQUUsUUFBUSxDQUFDO2lCQUN6QixHQUFHLENBQUMsVUFBVSxFQUFFLFFBQVEsQ0FBQztZQUU5QixJQUFJLElBQUksQ0FBQyxnQkFBZ0IsRUFBRTs7c0JBQ2pCLE1BQU0sR0FBRyxJQUFJLENBQUMsR0FBRyxJQUFJLENBQUMsUUFBUSxJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO2dCQUNqRSxPQUFPLEdBQUcsT0FBTyxDQUFDLEdBQUcsQ0FDakIsZUFBZSxFQUNmLFFBQVEsR0FBRyxNQUFNLENBQUMsQ0FBQzthQUMxQjtZQUVELElBQUksQ0FBQyxJQUFJLENBQUMsZ0JBQWdCLEVBQUU7Z0JBQ3hCLE1BQU0sR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7YUFDbkQ7WUFFRCxJQUFJLENBQUMsSUFBSSxDQUFDLGdCQUFnQixJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRTtnQkFDbEQsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsZUFBZSxFQUFFLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO2FBQ2hFO1lBRUQsSUFBSSxJQUFJLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3hCLEtBQUssTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFO29CQUNsRSxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7aUJBQ3pEO2FBQ0o7WUFFRCxPQUFPLEdBQUcsT0FBTyxDQUFDLEdBQUcsQ0FDakIsY0FBYyxFQUNkLG1DQUFtQyxDQUN0QyxDQUFDO1lBRUYsSUFBSSxDQUFDLElBQUk7aUJBQ0osSUFBSSxDQUFnQixJQUFJLENBQUMsYUFBYSxFQUFFLE1BQU0sRUFBRSxFQUFFLE9BQU8sRUFBRSxDQUFDO2lCQUM1RCxTQUFTOzs7O1lBQ04sYUFBYSxDQUFDLEVBQUU7Z0JBQ1osSUFBSSxDQUFDLEtBQUssQ0FBQyxlQUFlLEVBQUUsYUFBYSxDQUFDLENBQUM7Z0JBQzNDLElBQUksQ0FBQyx3QkFBd0IsQ0FDekIsYUFBYSxDQUFDLFlBQVksRUFDMUIsYUFBYSxDQUFDLGFBQWEsRUFDM0IsYUFBYSxDQUFDLFVBQVUsRUFDeEIsYUFBYSxDQUFDLEtBQUssQ0FDdEIsQ0FBQztnQkFFRixJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLGdCQUFnQixDQUFDLENBQUMsQ0FBQztnQkFDakUsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFDO1lBQzNCLENBQUM7Ozs7WUFDRCxHQUFHLENBQUMsRUFBRTtnQkFDRixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQ0FBZ0MsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDekQsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxlQUFlLENBQUMsYUFBYSxFQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ2pFLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNoQixDQUFDLEVBQ0osQ0FBQztRQUNWLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7Ozs7O0lBU00sWUFBWTtRQUVmLElBQUksQ0FBQyxJQUFJLENBQUMsbUJBQW1CLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxFQUFFO1lBQy9DLE1BQU0sSUFBSSxLQUFLLENBQ1gseUZBQXlGLENBQzVGLENBQUM7U0FDTDtRQUVELE9BQU8sSUFBSSxPQUFPOzs7OztRQUFDLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxFQUFFOztnQkFDL0IsTUFBTSxHQUFHLElBQUksVUFBVSxFQUFFO2lCQUN4QixHQUFHLENBQUMsWUFBWSxFQUFFLGVBQWUsQ0FBQztpQkFDbEMsR0FBRyxDQUFDLFdBQVcsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDO2lCQUMvQixHQUFHLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQyxLQUFLLENBQUM7aUJBQ3hCLEdBQUcsQ0FBQyxlQUFlLEVBQUUsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsZUFBZSxDQUFDLENBQUM7WUFFakUsSUFBSSxJQUFJLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3hCLE1BQU0sR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLGVBQWUsRUFBRSxJQUFJLENBQUMsaUJBQWlCLENBQUMsQ0FBQzthQUNoRTtZQUVELElBQUksSUFBSSxDQUFDLGlCQUFpQixFQUFFO2dCQUN4QixLQUFLLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsaUJBQWlCLENBQUMsRUFBRTtvQkFDbEUsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2lCQUN6RDthQUNKOztrQkFFSyxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQyxHQUFHLENBQ2pDLGNBQWMsRUFDZCxtQ0FBbUMsQ0FDdEM7WUFFRCxJQUFJLENBQUMsSUFBSTtpQkFDSixJQUFJLENBQWdCLElBQUksQ0FBQyxhQUFhLEVBQUUsTUFBTSxFQUFFLEVBQUUsT0FBTyxFQUFFLENBQUM7aUJBQzVELElBQUksQ0FBQyxTQUFTOzs7O1lBQUMsYUFBYSxDQUFDLEVBQUU7Z0JBQzVCLElBQUksYUFBYSxDQUFDLFFBQVEsRUFBRTtvQkFDeEIsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLGNBQWMsQ0FBQyxhQUFhLENBQUMsUUFBUSxFQUFFLGFBQWEsQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLENBQUM7eUJBQ3JGLElBQUksQ0FDRCxHQUFHOzs7O29CQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUMsRUFBQyxFQUN4QyxHQUFHOzs7O29CQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsYUFBYSxFQUFDLENBQzFCLENBQUM7aUJBQ1Q7cUJBQ0k7b0JBQ0QsT0FBTyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUM7aUJBQzVCO1lBQ0wsQ0FBQyxFQUFDLENBQUM7aUJBQ0YsU0FBUzs7OztZQUNOLGFBQWEsQ0FBQyxFQUFFO2dCQUNaLElBQUksQ0FBQyxLQUFLLENBQUMsdUJBQXVCLEVBQUUsYUFBYSxDQUFDLENBQUM7Z0JBQ25ELElBQUksQ0FBQyx3QkFBd0IsQ0FDekIsYUFBYSxDQUFDLFlBQVksRUFDMUIsYUFBYSxDQUFDLGFBQWEsRUFDM0IsYUFBYSxDQUFDLFVBQVUsRUFDeEIsYUFBYSxDQUFDLEtBQUssQ0FDdEIsQ0FBQztnQkFFRixJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLGdCQUFnQixDQUFDLENBQUMsQ0FBQztnQkFDakUsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxpQkFBaUIsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLENBQUM7Z0JBQ2xFLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQztZQUMzQixDQUFDOzs7O1lBQ0QsR0FBRyxDQUFDLEVBQUU7Z0JBQ0YsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsZ0NBQWdDLEVBQUUsR0FBRyxDQUFDLENBQUM7Z0JBQ3pELElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNuQixJQUFJLGVBQWUsQ0FBQyxxQkFBcUIsRUFBRSxHQUFHLENBQUMsQ0FDbEQsQ0FBQztnQkFDRixNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7WUFDaEIsQ0FBQyxFQUNKLENBQUM7UUFDVixDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7O0lBRVMsZ0NBQWdDO1FBQ3RDLElBQUksSUFBSSxDQUFDLHFDQUFxQyxFQUFFO1lBQzVDLE1BQU0sQ0FBQyxtQkFBbUIsQ0FDdEIsU0FBUyxFQUNULElBQUksQ0FBQyxxQ0FBcUMsQ0FDN0MsQ0FBQztZQUNGLElBQUksQ0FBQyxxQ0FBcUMsR0FBRyxJQUFJLENBQUM7U0FDckQ7SUFDTCxDQUFDOzs7OztJQUVTLCtCQUErQjtRQUNyQyxJQUFJLENBQUMsZ0NBQWdDLEVBQUUsQ0FBQztRQUV4QyxJQUFJLENBQUMscUNBQXFDOzs7O1FBQUcsQ0FBQyxDQUFlLEVBQUUsRUFBRTs7a0JBQ3ZELE9BQU8sR0FBRyxJQUFJLENBQUMsMEJBQTBCLENBQUMsQ0FBQyxDQUFDO1lBRWxELElBQUksQ0FBQyxRQUFRLENBQUM7Z0JBQ1Ysa0JBQWtCLEVBQUUsT0FBTztnQkFDM0IsMEJBQTBCLEVBQUUsSUFBSTtnQkFDaEMsWUFBWTs7OztnQkFBRSxHQUFHLENBQUMsRUFBRTtvQkFDaEIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQ25CLElBQUksZUFBZSxDQUFDLHNCQUFzQixFQUFFLEdBQUcsQ0FBQyxDQUNuRCxDQUFDO2dCQUNOLENBQUMsQ0FBQTtnQkFDRCxlQUFlOzs7Z0JBQUUsR0FBRyxFQUFFO29CQUNsQixJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLG9CQUFvQixDQUFDLENBQUMsQ0FBQztnQkFDekUsQ0FBQyxDQUFBO2FBQ0osQ0FBQyxDQUFDLEtBQUs7Ozs7WUFBQyxHQUFHLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsdUNBQXVDLEVBQUUsR0FBRyxDQUFDLEVBQUMsQ0FBQztRQUM5RSxDQUFDLENBQUEsQ0FBQztRQUVGLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FDbkIsU0FBUyxFQUNULElBQUksQ0FBQyxxQ0FBcUMsQ0FDN0MsQ0FBQztJQUNOLENBQUM7Ozs7Ozs7OztJQU9NLGFBQWEsQ0FBQyxTQUFpQixFQUFFLEVBQUUsUUFBUSxHQUFHLElBQUk7O2NBQy9DLE1BQU0sR0FBVyxJQUFJLENBQUMsaUJBQWlCLEVBQUUsSUFBSSxFQUFFO1FBRXJELElBQUksSUFBSSxDQUFDLDhCQUE4QixJQUFJLElBQUksQ0FBQyxlQUFlLEVBQUUsRUFBRTtZQUMvRCxNQUFNLENBQUMsZUFBZSxDQUFDLEdBQUcsSUFBSSxDQUFDLFVBQVUsRUFBRSxDQUFDO1NBQy9DO1FBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLEVBQUU7WUFDMUMsTUFBTSxJQUFJLEtBQUssQ0FDWCx5RkFBeUYsQ0FDNUYsQ0FBQztTQUNMO1FBRUQsSUFBSSxPQUFPLFFBQVEsS0FBSyxXQUFXLEVBQUU7WUFDakMsTUFBTSxJQUFJLEtBQUssQ0FBQyxrREFBa0QsQ0FBQyxDQUFDO1NBQ3ZFOztjQUVLLGNBQWMsR0FBRyxRQUFRLENBQUMsY0FBYyxDQUMxQyxJQUFJLENBQUMsdUJBQXVCLENBQy9CO1FBRUQsSUFBSSxjQUFjLEVBQUU7WUFDaEIsUUFBUSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsY0FBYyxDQUFDLENBQUM7U0FDN0M7UUFFRCxJQUFJLENBQUMsb0JBQW9CLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDOztjQUVwQyxNQUFNLEdBQUcsUUFBUSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQUM7UUFDL0MsTUFBTSxDQUFDLEVBQUUsR0FBRyxJQUFJLENBQUMsdUJBQXVCLENBQUM7UUFFekMsSUFBSSxDQUFDLCtCQUErQixFQUFFLENBQUM7O2NBRWpDLFdBQVcsR0FBRyxJQUFJLENBQUMsd0JBQXdCLElBQUksSUFBSSxDQUFDLFdBQVc7UUFDckUsSUFBSSxDQUFDLGNBQWMsQ0FBQyxJQUFJLEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRSxRQUFRLEVBQUUsTUFBTSxDQUFDLENBQUMsSUFBSTs7OztRQUFDLEdBQUcsQ0FBQyxFQUFFO1lBQ3RFLE1BQU0sQ0FBQyxZQUFZLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxDQUFDO1lBRWhDLElBQUksQ0FBQyxJQUFJLENBQUMsdUJBQXVCLEVBQUU7Z0JBQy9CLE1BQU0sQ0FBQyxLQUFLLENBQUMsU0FBUyxDQUFDLEdBQUcsTUFBTSxDQUFDO2FBQ3BDO1lBQ0QsUUFBUSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDdEMsQ0FBQyxFQUFDLENBQUM7O2NBRUcsTUFBTSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUMzQixNQUFNOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLFlBQVksZUFBZSxFQUFDLEVBQ3pDLEtBQUssRUFBRSxDQUNWOztjQUNLLE9BQU8sR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FDNUIsTUFBTTs7OztRQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxvQkFBb0IsRUFBQyxFQUM1QyxLQUFLLEVBQUUsQ0FDVjs7Y0FDSyxPQUFPLEdBQUcsRUFBRSxDQUNkLElBQUksZUFBZSxDQUFDLHdCQUF3QixFQUFFLElBQUksQ0FBQyxDQUN0RCxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLG9CQUFvQixDQUFDLENBQUM7UUFFeEMsT0FBTyxJQUFJLENBQUMsQ0FBQyxNQUFNLEVBQUUsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFDO2FBQ2xDLElBQUksQ0FDRCxHQUFHOzs7O1FBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDSixJQUFJLENBQUMsQ0FBQyxJQUFJLEtBQUssd0JBQXdCLEVBQUU7Z0JBQ3JDLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDO2FBQzlCO1FBQ0wsQ0FBQyxFQUFDLEVBQ0YsR0FBRzs7OztRQUFDLENBQUMsQ0FBQyxFQUFFO1lBQ0osSUFBSSxDQUFDLFlBQVksZUFBZSxFQUFFO2dCQUM5QixNQUFNLENBQUMsQ0FBQzthQUNYO1lBQ0QsT0FBTyxDQUFDLENBQUM7UUFDYixDQUFDLEVBQUMsQ0FDTDthQUNBLFNBQVMsRUFBRSxDQUFDO0lBQ3JCLENBQUM7Ozs7O0lBRU0sdUJBQXVCLENBQUMsT0FBNkM7UUFDeEUsT0FBTyxHQUFHLE9BQU8sSUFBSSxFQUFFLENBQUM7UUFDeEIsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLElBQUksRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDLHdCQUF3QixFQUFFLEtBQUssRUFBRTtZQUN6RSxPQUFPLEVBQUUsT0FBTztTQUNuQixDQUFDLENBQUMsSUFBSTs7OztRQUFDLEdBQUcsQ0FBQyxFQUFFO1lBQ1YsT0FBTyxJQUFJLE9BQU87Ozs7O1lBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7O29CQUMvQixTQUFTLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsUUFBUSxFQUFFLElBQUksQ0FBQyxzQkFBc0IsQ0FBQyxPQUFPLENBQUMsQ0FBQzs7c0JBRTFFLE9BQU87OztnQkFBRyxHQUFHLEVBQUU7b0JBQ2pCLE1BQU0sQ0FBQyxtQkFBbUIsQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUM7b0JBQ2hELFNBQVMsQ0FBQyxLQUFLLEVBQUUsQ0FBQztvQkFDbEIsU0FBUyxHQUFHLElBQUksQ0FBQztnQkFDckIsQ0FBQyxDQUFBOztzQkFFSyxRQUFROzs7O2dCQUFHLENBQUMsQ0FBZSxFQUFFLEVBQUU7OzBCQUMzQixPQUFPLEdBQUcsSUFBSSxDQUFDLDBCQUEwQixDQUFDLENBQUMsQ0FBQztvQkFFbEQsSUFBSSxDQUFDLFFBQVEsQ0FBQzt3QkFDVixrQkFBa0IsRUFBRSxPQUFPO3dCQUMzQiwwQkFBMEIsRUFBRSxJQUFJO3FCQUNuQyxDQUFDLENBQUMsSUFBSTs7O29CQUFDLEdBQUcsRUFBRTt3QkFDVCxPQUFPLEVBQUUsQ0FBQzt3QkFDVixPQUFPLEVBQUUsQ0FBQztvQkFDZCxDQUFDOzs7O29CQUFFLEdBQUcsQ0FBQyxFQUFFO3dCQUNMLE9BQU8sRUFBRSxDQUFDO3dCQUNWLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztvQkFDaEIsQ0FBQyxFQUFDLENBQUM7Z0JBQ1AsQ0FBQyxDQUFBO2dCQUVELE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUM7WUFDakQsQ0FBQyxFQUFDLENBQUM7UUFDUCxDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7OztJQUVTLHNCQUFzQixDQUFDLE9BQTRDOzs7Y0FFbkUsTUFBTSxHQUFHLE9BQU8sQ0FBQyxNQUFNLElBQUksR0FBRzs7Y0FDOUIsS0FBSyxHQUFHLE9BQU8sQ0FBQyxLQUFLLElBQUksR0FBRzs7Y0FDNUIsSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLEtBQUssR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLEtBQUssR0FBRyxDQUFDLENBQUM7O2NBQ3ZDLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDO1FBQzlDLE9BQU8sZ0NBQWdDLEtBQUssV0FBVyxNQUFNLFFBQVEsR0FBRyxTQUFTLElBQUksRUFBRSxDQUFDO0lBQzVGLENBQUM7Ozs7OztJQUVTLDBCQUEwQixDQUFDLENBQWU7O1lBQzVDLGNBQWMsR0FBRyxHQUFHO1FBRXhCLElBQUksSUFBSSxDQUFDLDBCQUEwQixFQUFFO1lBQ2pDLGNBQWMsSUFBSSxJQUFJLENBQUMsMEJBQTBCLENBQUM7U0FDckQ7UUFFRCxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLElBQUksSUFBSSxPQUFPLENBQUMsQ0FBQyxJQUFJLEtBQUssUUFBUSxFQUFFO1lBQzdDLE9BQU87U0FDVjs7Y0FFSyxlQUFlLEdBQVcsQ0FBQyxDQUFDLElBQUk7UUFFdEMsSUFBSSxDQUFDLGVBQWUsQ0FBQyxVQUFVLENBQUMsY0FBYyxDQUFDLEVBQUU7WUFDN0MsT0FBTztTQUNWO1FBRUQsT0FBTyxHQUFHLEdBQUcsZUFBZSxDQUFDLE1BQU0sQ0FBQyxjQUFjLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDL0QsQ0FBQzs7Ozs7SUFFUyxzQkFBc0I7UUFDNUIsSUFBSSxDQUFDLElBQUksQ0FBQyxvQkFBb0IsRUFBRTtZQUM1QixPQUFPLEtBQUssQ0FBQztTQUNoQjtRQUNELElBQUksQ0FBQyxJQUFJLENBQUMscUJBQXFCLEVBQUU7WUFDN0IsT0FBTyxDQUFDLElBQUksQ0FDUix5RUFBeUUsQ0FDNUUsQ0FBQztZQUNGLE9BQU8sS0FBSyxDQUFDO1NBQ2hCOztjQUNLLFlBQVksR0FBRyxJQUFJLENBQUMsZUFBZSxFQUFFO1FBQzNDLElBQUksQ0FBQyxZQUFZLEVBQUU7WUFDZixPQUFPLENBQUMsSUFBSSxDQUNSLGlFQUFpRSxDQUNwRSxDQUFDO1lBQ0YsT0FBTyxLQUFLLENBQUM7U0FDaEI7UUFDRCxJQUFJLE9BQU8sUUFBUSxLQUFLLFdBQVcsRUFBRTtZQUNqQyxPQUFPLEtBQUssQ0FBQztTQUNoQjtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2hCLENBQUM7Ozs7O0lBRVMsOEJBQThCO1FBQ3BDLElBQUksQ0FBQywrQkFBK0IsRUFBRSxDQUFDO1FBRXZDLElBQUksQ0FBQyx5QkFBeUI7Ozs7UUFBRyxDQUFDLENBQWUsRUFBRSxFQUFFOztrQkFDM0MsTUFBTSxHQUFHLENBQUMsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFOztrQkFDL0IsTUFBTSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFO1lBRXhDLElBQUksQ0FBQyxLQUFLLENBQUMsMkJBQTJCLENBQUMsQ0FBQztZQUV4QyxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxNQUFNLENBQUMsRUFBRTtnQkFDNUIsSUFBSSxDQUFDLEtBQUssQ0FDTiwyQkFBMkIsRUFDM0IsY0FBYyxFQUNkLE1BQU0sRUFDTixVQUFVLEVBQ1YsTUFBTSxDQUNULENBQUM7YUFDTDtZQUVELHlEQUF5RDtZQUN6RCxRQUFRLENBQUMsQ0FBQyxJQUFJLEVBQUU7Z0JBQ1osS0FBSyxXQUFXO29CQUNaLElBQUksQ0FBQyxzQkFBc0IsRUFBRSxDQUFDO29CQUM5QixNQUFNO2dCQUNWLEtBQUssU0FBUztvQkFDVixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUc7OztvQkFBQyxHQUFHLEVBQUU7d0JBQ2pCLElBQUksQ0FBQyxtQkFBbUIsRUFBRSxDQUFDO29CQUMvQixDQUFDLEVBQUMsQ0FBQztvQkFDSCxNQUFNO2dCQUNWLEtBQUssT0FBTztvQkFDUixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUc7OztvQkFBQyxHQUFHLEVBQUU7d0JBQ2pCLElBQUksQ0FBQyxrQkFBa0IsRUFBRSxDQUFDO29CQUM5QixDQUFDLEVBQUMsQ0FBQztvQkFDSCxNQUFNO2FBQ2I7WUFFRCxJQUFJLENBQUMsS0FBSyxDQUFDLHFDQUFxQyxFQUFFLENBQUMsQ0FBQyxDQUFDO1FBQ3pELENBQUMsQ0FBQSxDQUFDO1FBRUYsZ0ZBQWdGO1FBQ2hGLElBQUksQ0FBQyxNQUFNLENBQUMsaUJBQWlCOzs7UUFBQyxHQUFHLEVBQUU7WUFDL0IsTUFBTSxDQUFDLGdCQUFnQixDQUFDLFNBQVMsRUFBRSxJQUFJLENBQUMseUJBQXlCLENBQUMsQ0FBQztRQUN2RSxDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7O0lBRVMsc0JBQXNCO1FBQzVCLElBQUksQ0FBQyxLQUFLLENBQUMsZUFBZSxFQUFFLG1CQUFtQixDQUFDLENBQUM7SUFDckQsQ0FBQzs7Ozs7SUFFUyxtQkFBbUI7UUFDekIsNERBQTREO1FBQzVELElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksY0FBYyxDQUFDLGlCQUFpQixDQUFDLENBQUMsQ0FBQztRQUMvRCxJQUFJLENBQUMscUJBQXFCLEVBQUUsQ0FBQztRQUM3QixJQUFJLElBQUksQ0FBQyx3QkFBd0IsRUFBRTtZQUMvQixJQUFJLENBQUMsYUFBYSxFQUFFLENBQUMsS0FBSzs7OztZQUFDLENBQUMsQ0FBQyxFQUFFLENBQzNCLElBQUksQ0FBQyxLQUFLLENBQUMsNkNBQTZDLENBQUMsRUFDNUQsQ0FBQztZQUNGLElBQUksQ0FBQyxzQ0FBc0MsRUFBRSxDQUFDO1NBQ2pEO2FBQU07WUFDSCxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGNBQWMsQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDLENBQUM7WUFDbEUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUNyQjtJQUNMLENBQUM7Ozs7O0lBRVMsc0NBQXNDO1FBQzVDLElBQUksQ0FBQyxNQUFNO2FBQ04sSUFBSSxDQUNELE1BQU07Ozs7UUFDRixDQUFDLENBQWEsRUFBRSxFQUFFLENBQ2QsQ0FBQyxDQUFDLElBQUksS0FBSyxvQkFBb0I7WUFDL0IsQ0FBQyxDQUFDLElBQUksS0FBSyx3QkFBd0I7WUFDbkMsQ0FBQyxDQUFDLElBQUksS0FBSyxzQkFBc0IsRUFDeEMsRUFDRCxLQUFLLEVBQUUsQ0FDVjthQUNBLFNBQVM7Ozs7UUFBQyxDQUFDLENBQUMsRUFBRTtZQUNYLElBQUksQ0FBQyxDQUFDLElBQUksS0FBSyxvQkFBb0IsRUFBRTtnQkFDakMsSUFBSSxDQUFDLEtBQUssQ0FBQyxtREFBbUQsQ0FBQyxDQUFDO2dCQUNoRSxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGNBQWMsQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDLENBQUM7Z0JBQ2xFLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUM7YUFDckI7UUFDTCxDQUFDLEVBQUMsQ0FBQztJQUNYLENBQUM7Ozs7O0lBRVMsa0JBQWtCO1FBQ3hCLElBQUksQ0FBQyxxQkFBcUIsRUFBRSxDQUFDO1FBQzdCLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksY0FBYyxDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUM7SUFDakUsQ0FBQzs7Ozs7SUFFUywrQkFBK0I7UUFDckMsSUFBSSxJQUFJLENBQUMseUJBQXlCLEVBQUU7WUFDaEMsTUFBTSxDQUFDLG1CQUFtQixDQUFDLFNBQVMsRUFBRSxJQUFJLENBQUMseUJBQXlCLENBQUMsQ0FBQztZQUN0RSxJQUFJLENBQUMseUJBQXlCLEdBQUcsSUFBSSxDQUFDO1NBQ3pDO0lBQ0wsQ0FBQzs7Ozs7SUFFUyxnQkFBZ0I7UUFDdEIsSUFBSSxDQUFDLElBQUksQ0FBQyxzQkFBc0IsRUFBRSxFQUFFO1lBQ2hDLE9BQU87U0FDVjs7Y0FFSyxjQUFjLEdBQUcsUUFBUSxDQUFDLGNBQWMsQ0FBQyxJQUFJLENBQUMsc0JBQXNCLENBQUM7UUFDM0UsSUFBSSxjQUFjLEVBQUU7WUFDaEIsUUFBUSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsY0FBYyxDQUFDLENBQUM7U0FDN0M7O2NBRUssTUFBTSxHQUFHLFFBQVEsQ0FBQyxhQUFhLENBQUMsUUFBUSxDQUFDO1FBQy9DLE1BQU0sQ0FBQyxFQUFFLEdBQUcsSUFBSSxDQUFDLHNCQUFzQixDQUFDO1FBRXhDLElBQUksQ0FBQyw4QkFBOEIsRUFBRSxDQUFDOztjQUVoQyxHQUFHLEdBQUcsSUFBSSxDQUFDLHFCQUFxQjtRQUN0QyxNQUFNLENBQUMsWUFBWSxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQztRQUNoQyxNQUFNLENBQUMsS0FBSyxDQUFDLE9BQU8sR0FBRyxNQUFNLENBQUM7UUFDOUIsUUFBUSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLENBQUM7UUFFbEMsSUFBSSxDQUFDLHNCQUFzQixFQUFFLENBQUM7SUFDbEMsQ0FBQzs7Ozs7SUFFUyxzQkFBc0I7UUFDNUIsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7UUFDN0IsSUFBSSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUI7OztRQUFDLEdBQUcsRUFBRTtZQUMvQixJQUFJLENBQUMsaUJBQWlCLEdBQUcsV0FBVyxDQUNoQyxJQUFJLENBQUMsWUFBWSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsRUFDNUIsSUFBSSxDQUFDLHFCQUFxQixDQUM3QixDQUFDO1FBQ04sQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7OztJQUVTLHFCQUFxQjtRQUMzQixJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRTtZQUN4QixhQUFhLENBQUMsSUFBSSxDQUFDLGlCQUFpQixDQUFDLENBQUM7WUFDdEMsSUFBSSxDQUFDLGlCQUFpQixHQUFHLElBQUksQ0FBQztTQUNqQztJQUNMLENBQUM7Ozs7O0lBRVMsWUFBWTs7Y0FDWixNQUFNLEdBQVEsUUFBUSxDQUFDLGNBQWMsQ0FBQyxJQUFJLENBQUMsc0JBQXNCLENBQUM7UUFFeEUsSUFBSSxDQUFDLE1BQU0sRUFBRTtZQUNULElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUNaLGtDQUFrQyxFQUNsQyxJQUFJLENBQUMsc0JBQXNCLENBQzlCLENBQUM7U0FDTDs7Y0FFSyxZQUFZLEdBQUcsSUFBSSxDQUFDLGVBQWUsRUFBRTtRQUUzQyxJQUFJLENBQUMsWUFBWSxFQUFFO1lBQ2YsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7U0FDaEM7O2NBRUssT0FBTyxHQUFHLElBQUksQ0FBQyxRQUFRLEdBQUcsR0FBRyxHQUFHLFlBQVk7UUFDbEQsTUFBTSxDQUFDLGFBQWEsQ0FBQyxXQUFXLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUMzRCxDQUFDOzs7Ozs7Ozs7O0lBRWUsY0FBYyxDQUMxQixLQUFLLEdBQUcsRUFBRSxFQUNWLFNBQVMsR0FBRyxFQUFFLEVBQ2QsaUJBQWlCLEdBQUcsRUFBRSxFQUN0QixRQUFRLEdBQUcsS0FBSyxFQUNoQixTQUFpQixFQUFFOzs7a0JBRWIsSUFBSSxHQUFHLElBQUk7O2dCQUViLFdBQW1CO1lBRXZCLElBQUksaUJBQWlCLEVBQUU7Z0JBQ25CLFdBQVcsR0FBRyxpQkFBaUIsQ0FBQzthQUNuQztpQkFBTTtnQkFDSCxXQUFXLEdBQUcsSUFBSSxDQUFDLFdBQVcsQ0FBQzthQUNsQzs7a0JBRUssS0FBSyxHQUFHLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixFQUFFO1lBRTdDLElBQUksS0FBSyxFQUFFO2dCQUNQLEtBQUssR0FBRyxLQUFLLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxtQkFBbUIsR0FBRyxLQUFLLENBQUM7YUFDM0Q7aUJBQU07Z0JBQ0gsS0FBSyxHQUFHLEtBQUssQ0FBQzthQUNqQjtZQUVELElBQUksQ0FBQyxJQUFJLENBQUMsa0JBQWtCLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxFQUFFO2dCQUN4QyxNQUFNLElBQUksS0FBSyxDQUNYLHdEQUF3RCxDQUMzRCxDQUFDO2FBQ0w7WUFFRCxJQUFJLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxFQUFFO2dCQUMxQixJQUFJLENBQUMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDO2FBQ2hEO2lCQUFNO2dCQUNILElBQUksSUFBSSxDQUFDLElBQUksSUFBSSxJQUFJLENBQUMsa0JBQWtCLEVBQUU7b0JBQ3RDLElBQUksQ0FBQyxZQUFZLEdBQUcsZ0JBQWdCLENBQUM7aUJBQ3hDO3FCQUFNLElBQUksSUFBSSxDQUFDLElBQUksSUFBSSxDQUFDLElBQUksQ0FBQyxrQkFBa0IsRUFBRTtvQkFDOUMsSUFBSSxDQUFDLFlBQVksR0FBRyxVQUFVLENBQUM7aUJBQ2xDO3FCQUFNO29CQUNILElBQUksQ0FBQyxZQUFZLEdBQUcsT0FBTyxDQUFDO2lCQUMvQjthQUNKOztrQkFFSyxjQUFjLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRzs7Z0JBRTlELEtBQUssR0FBRyxJQUFJLENBQUMsS0FBSztZQUV0QixJQUFJLElBQUksQ0FBQyxJQUFJLElBQUksQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLG9CQUFvQixDQUFDLEVBQUU7Z0JBQ2pELEtBQUssR0FBRyxTQUFTLEdBQUcsS0FBSyxDQUFDO2FBQzdCOztnQkFFRyxHQUFHLEdBQ0gsSUFBSSxDQUFDLFFBQVE7Z0JBQ2IsY0FBYztnQkFDZCxnQkFBZ0I7Z0JBQ2hCLGtCQUFrQixDQUFDLElBQUksQ0FBQyxZQUFZLENBQUM7Z0JBQ3JDLGFBQWE7Z0JBQ2Isa0JBQWtCLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQztnQkFDakMsU0FBUztnQkFDVCxrQkFBa0IsQ0FBQyxLQUFLLENBQUM7Z0JBQ3pCLGdCQUFnQjtnQkFDaEIsa0JBQWtCLENBQUMsV0FBVyxDQUFDO2dCQUMvQixTQUFTO2dCQUNULGtCQUFrQixDQUFDLEtBQUssQ0FBQztZQUU3QixJQUFJLElBQUksQ0FBQyxZQUFZLEtBQUssTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLFdBQVcsRUFBRTtzQkFDN0MsQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLEdBQUcsTUFBTSxJQUFJLENBQUMsa0NBQWtDLEVBQUU7Z0JBQzdFLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGVBQWUsRUFBRSxRQUFRLENBQUMsQ0FBQztnQkFDakQsR0FBRyxJQUFJLGtCQUFrQixHQUFHLFNBQVMsQ0FBQztnQkFDdEMsR0FBRyxJQUFJLDZCQUE2QixDQUFDO2FBQ3hDO1lBRUQsSUFBSSxTQUFTLEVBQUU7Z0JBQ1gsR0FBRyxJQUFJLGNBQWMsR0FBRyxrQkFBa0IsQ0FBQyxTQUFTLENBQUMsQ0FBQzthQUN6RDtZQUVELElBQUksSUFBSSxDQUFDLFFBQVEsRUFBRTtnQkFDZixHQUFHLElBQUksWUFBWSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQzthQUMzRDtZQUVELElBQUksSUFBSSxDQUFDLElBQUksRUFBRTtnQkFDWCxHQUFHLElBQUksU0FBUyxHQUFHLGtCQUFrQixDQUFDLEtBQUssQ0FBQyxDQUFDO2FBQ2hEO1lBRUQsSUFBSSxRQUFRLEVBQUU7Z0JBQ1YsR0FBRyxJQUFJLGNBQWMsQ0FBQzthQUN6QjtZQUVELEtBQUssTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsRUFBRTtnQkFDbkMsR0FBRztvQkFDQyxHQUFHLEdBQUcsa0JBQWtCLENBQUMsR0FBRyxDQUFDLEdBQUcsR0FBRyxHQUFHLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2FBQzdFO1lBRUQsSUFBSSxJQUFJLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3hCLEtBQUssTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFO29CQUNsRSxHQUFHO3dCQUNDLEdBQUcsR0FBRyxHQUFHLEdBQUcsR0FBRyxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2lCQUN6RTthQUNKO1lBRUQsT0FBTyxHQUFHLENBQUM7UUFFZixDQUFDO0tBQUE7Ozs7OztJQUVELHdCQUF3QixDQUNwQixlQUFlLEdBQUcsRUFBRSxFQUNwQixTQUEwQixFQUFFO1FBRTVCLElBQUksSUFBSSxDQUFDLGNBQWMsRUFBRTtZQUNyQixPQUFPO1NBQ1Y7UUFFRCxJQUFJLENBQUMsY0FBYyxHQUFHLElBQUksQ0FBQztRQUUzQixJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRTtZQUMxQyxNQUFNLElBQUksS0FBSyxDQUNYLG9GQUFvRixDQUN2RixDQUFDO1NBQ0w7O1lBRUcsU0FBUyxHQUFXLEVBQUU7O1lBQ3RCLFNBQVMsR0FBVyxJQUFJO1FBRTVCLElBQUksT0FBTyxNQUFNLEtBQUssUUFBUSxFQUFFO1lBQzVCLFNBQVMsR0FBRyxNQUFNLENBQUM7U0FDdEI7YUFBTSxJQUFJLE9BQU8sTUFBTSxLQUFLLFFBQVEsRUFBRTtZQUNuQyxTQUFTLEdBQUcsTUFBTSxDQUFDO1NBQ3RCO1FBRUQsSUFBSSxDQUFDLGNBQWMsQ0FBQyxlQUFlLEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxLQUFLLEVBQUUsU0FBUyxDQUFDO2FBQ2xFLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQzthQUN6QixLQUFLOzs7O1FBQUMsS0FBSyxDQUFDLEVBQUU7WUFDWCxPQUFPLENBQUMsS0FBSyxDQUFDLDJCQUEyQixFQUFFLEtBQUssQ0FBQyxDQUFDO1lBQ2xELElBQUksQ0FBQyxjQUFjLEdBQUcsS0FBSyxDQUFDO1FBQ2hDLENBQUMsRUFBQyxDQUFDO0lBQ1gsQ0FBQzs7Ozs7Ozs7Ozs7SUFXTSxnQkFBZ0IsQ0FDbkIsZUFBZSxHQUFHLEVBQUUsRUFDcEIsU0FBMEIsRUFBRTtRQUU1QixJQUFJLElBQUksQ0FBQyxRQUFRLEtBQUssRUFBRSxFQUFFO1lBQ3RCLElBQUksQ0FBQyx3QkFBd0IsQ0FBQyxlQUFlLEVBQUUsTUFBTSxDQUFDLENBQUM7U0FDMUQ7YUFBTTtZQUNILElBQUksQ0FBQyxNQUFNO2lCQUNOLElBQUksQ0FBQyxNQUFNOzs7O1lBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLDJCQUEyQixFQUFDLENBQUM7aUJBQ3pELFNBQVM7Ozs7WUFBQyxDQUFDLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyx3QkFBd0IsQ0FBQyxlQUFlLEVBQUUsTUFBTSxDQUFDLEVBQUMsQ0FBQztTQUMvRTtJQUNMLENBQUM7Ozs7Ozs7SUFPTSxpQkFBaUI7UUFDdEIsSUFBSSxDQUFDLGNBQWMsR0FBRyxLQUFLLENBQUM7SUFDOUIsQ0FBQzs7Ozs7O0lBRVMsMkJBQTJCLENBQUMsT0FBcUI7O2NBQ2pELElBQUksR0FBRyxJQUFJO1FBQ2pCLElBQUksT0FBTyxDQUFDLGVBQWUsRUFBRTs7a0JBQ25CLFdBQVcsR0FBRztnQkFDaEIsUUFBUSxFQUFFLElBQUksQ0FBQyxpQkFBaUIsRUFBRTtnQkFDbEMsT0FBTyxFQUFFLElBQUksQ0FBQyxVQUFVLEVBQUU7Z0JBQzFCLFdBQVcsRUFBRSxJQUFJLENBQUMsY0FBYyxFQUFFO2dCQUNsQyxLQUFLLEVBQUUsSUFBSSxDQUFDLEtBQUs7YUFDcEI7WUFDRCxPQUFPLENBQUMsZUFBZSxDQUFDLFdBQVcsQ0FBQyxDQUFDO1NBQ3hDO0lBQ0wsQ0FBQzs7Ozs7Ozs7O0lBRVMsd0JBQXdCLENBQzlCLFdBQW1CLEVBQ25CLFlBQW9CLEVBQ3BCLFNBQWlCLEVBQ2pCLGFBQXFCO1FBRXJCLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGNBQWMsRUFBRSxXQUFXLENBQUMsQ0FBQztRQUNuRCxJQUFJLGFBQWEsRUFBRTtZQUNmLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGdCQUFnQixFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDckY7UUFDRCxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyx3QkFBd0IsRUFBRSxFQUFFLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRSxDQUFDLENBQUM7UUFDakUsSUFBSSxTQUFTLEVBQUU7O2tCQUNMLHFCQUFxQixHQUFHLFNBQVMsR0FBRyxJQUFJOztrQkFDeEMsR0FBRyxHQUFHLElBQUksSUFBSSxFQUFFOztrQkFDaEIsU0FBUyxHQUFHLEdBQUcsQ0FBQyxPQUFPLEVBQUUsR0FBRyxxQkFBcUI7WUFDdkQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsWUFBWSxFQUFFLEVBQUUsR0FBRyxTQUFTLENBQUMsQ0FBQztTQUN2RDtRQUVELElBQUksWUFBWSxFQUFFO1lBQ2QsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsZUFBZSxFQUFFLFlBQVksQ0FBQyxDQUFDO1NBQ3hEO0lBQ0wsQ0FBQzs7Ozs7O0lBTU0sUUFBUSxDQUFDLFVBQXdCLElBQUk7UUFDeEMsSUFBSSxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksS0FBSyxNQUFNLEVBQUU7WUFDckMsT0FBTyxJQUFJLENBQUMsZ0JBQWdCLEVBQUUsQ0FBQyxJQUFJOzs7O1lBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxJQUFJLEVBQUMsQ0FBQztTQUNsRDthQUNJO1lBQ0QsT0FBTyxJQUFJLENBQUMsb0JBQW9CLENBQUMsT0FBTyxDQUFDLENBQUM7U0FDN0M7SUFDTCxDQUFDOzs7Ozs7SUFHTyxnQkFBZ0IsQ0FBQyxXQUFtQjtRQUN4QyxJQUFJLENBQUMsV0FBVyxJQUFJLFdBQVcsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO1lBQzFDLE9BQU8sRUFBRSxDQUFDO1NBQ2I7UUFFRCxJQUFJLFdBQVcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEtBQUssR0FBRyxFQUFFO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ3ZDO1FBRUQsT0FBTyxJQUFJLENBQUMsU0FBUyxDQUFDLGdCQUFnQixDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBR3hELENBQUM7Ozs7SUFFTSxnQkFBZ0I7O2NBRWIsS0FBSyxHQUFHLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQzs7Y0FFckQsSUFBSSxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUM7O2NBQ3BCLEtBQUssR0FBRyxLQUFLLENBQUMsT0FBTyxDQUFDOztjQUV0QixJQUFJLEdBQUcsUUFBUSxDQUFDLElBQUk7YUFDVCxPQUFPLENBQUMsbUJBQW1CLEVBQUUsRUFBRSxDQUFDO2FBQ2hDLE9BQU8sQ0FBQyxvQkFBb0IsRUFBRSxFQUFFLENBQUM7YUFDakMsT0FBTyxDQUFDLG9CQUFvQixFQUFFLEVBQUUsQ0FBQzthQUNqQyxPQUFPLENBQUMsNEJBQTRCLEVBQUUsRUFBRSxDQUFDO1FBRTFELE9BQU8sQ0FBQyxZQUFZLENBQUMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7WUFFMUMsQ0FBQyxZQUFZLEVBQUUsU0FBUyxDQUFDLEdBQUcsSUFBSSxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUM7UUFDdEQsSUFBSSxDQUFDLEtBQUssR0FBRyxTQUFTLENBQUM7UUFFdkIsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLEVBQUU7WUFDaEIsSUFBSSxDQUFDLEtBQUssQ0FBQyx1QkFBdUIsQ0FBQyxDQUFDO1lBQ3BDLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxFQUFFLEVBQUUsS0FBSyxDQUFDLENBQUM7O2tCQUMzQixHQUFHLEdBQUcsSUFBSSxlQUFlLENBQUMsWUFBWSxFQUFFLEVBQUUsRUFBRSxLQUFLLENBQUM7WUFDeEQsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7WUFDN0IsT0FBTyxPQUFPLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1NBQzlCO1FBRUQsSUFBSSxDQUFDLFlBQVksRUFBRTtZQUNmLE9BQU8sT0FBTyxDQUFDLE9BQU8sRUFBRSxDQUFDO1NBQzVCOztjQUVLLE9BQU8sR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFDLFlBQVksQ0FBQztRQUNoRCxJQUFJLENBQUMsT0FBTyxFQUFFOztrQkFDSixLQUFLLEdBQUcsSUFBSSxlQUFlLENBQUMsd0JBQXdCLEVBQUUsSUFBSSxDQUFDO1lBQ2pFLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQy9CLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUNoQztRQUVELElBQUksSUFBSSxFQUFFO1lBQ04sT0FBTyxJQUFJLE9BQU87Ozs7O1lBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7Z0JBQ25DLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJOzs7O2dCQUFDLE1BQU0sQ0FBQyxFQUFFO29CQUN0QyxPQUFPLEVBQUUsQ0FBQztnQkFDZCxDQUFDLEVBQUMsQ0FBQyxLQUFLOzs7O2dCQUFDLEdBQUcsQ0FBQyxFQUFFO29CQUNYLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDaEIsQ0FBQyxFQUFDLENBQUM7WUFDUCxDQUFDLEVBQUMsQ0FBQztTQUNOO2FBQU07WUFDSCxPQUFPLE9BQU8sQ0FBQyxPQUFPLEVBQUUsQ0FBQztTQUM1QjtJQUNMLENBQUM7Ozs7Ozs7SUFLTyxnQkFBZ0IsQ0FBQyxJQUFZOztZQUM3QixNQUFNLEdBQUcsSUFBSSxVQUFVLEVBQUU7YUFDeEIsR0FBRyxDQUFDLFlBQVksRUFBRSxvQkFBb0IsQ0FBQzthQUN2QyxHQUFHLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBQzthQUNqQixHQUFHLENBQUMsY0FBYyxFQUFFLElBQUksQ0FBQyxXQUFXLENBQUM7UUFFMUMsSUFBSSxDQUFDLElBQUksQ0FBQyxXQUFXLEVBQUU7O2tCQUNiLFlBQVksR0FBRyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUM7WUFFM0QsSUFBSSxDQUFDLFlBQVksRUFBRTtnQkFDZixPQUFPLENBQUMsSUFBSSxDQUFDLDBDQUEwQyxDQUFDLENBQUM7YUFDNUQ7aUJBQU07Z0JBQ0gsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsZUFBZSxFQUFFLFlBQVksQ0FBQyxDQUFDO2FBQ3REO1NBQ0o7UUFFRCxPQUFPLElBQUksQ0FBQyxvQkFBb0IsQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUM3QyxDQUFDOzs7Ozs7SUFFTyxvQkFBb0IsQ0FBQyxNQUFrQjs7WUFFdkMsT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFO2FBQ04sR0FBRyxDQUFDLGNBQWMsRUFBRSxtQ0FBbUMsQ0FBQztRQUVqRixJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsRUFBRTtZQUMvQyxNQUFNLElBQUksS0FBSyxDQUFDLGdFQUFnRSxDQUFDLENBQUM7U0FDckY7UUFFRCxJQUFJLElBQUksQ0FBQyxnQkFBZ0IsRUFBRTs7a0JBQ2pCLE1BQU0sR0FBRyxJQUFJLENBQUMsR0FBRyxJQUFJLENBQUMsUUFBUSxJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO1lBQ2pFLE9BQU8sR0FBRyxPQUFPLENBQUMsR0FBRyxDQUNqQixlQUFlLEVBQ2YsUUFBUSxHQUFHLE1BQU0sQ0FBQyxDQUFDO1NBQzFCO1FBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsRUFBRTtZQUN4QixNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLEVBQUUsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1NBQ25EO1FBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsSUFBSSxJQUFJLENBQUMsaUJBQWlCLEVBQUU7WUFDbEQsTUFBTSxHQUFHLE1BQU0sQ0FBQyxHQUFHLENBQUMsZUFBZSxFQUFFLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO1NBQ2hFO1FBRUQsT0FBTyxJQUFJLE9BQU87Ozs7O1FBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTSxFQUFFLEVBQUU7WUFFbkMsSUFBSSxJQUFJLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ3hCLEtBQUssSUFBSSxHQUFHLElBQUksTUFBTSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFO29CQUNoRSxNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7aUJBQ3pEO2FBQ0o7WUFFRCxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBZ0IsSUFBSSxDQUFDLGFBQWEsRUFBRSxNQUFNLEVBQUUsRUFBRSxPQUFPLEVBQUUsQ0FBQyxDQUFDLFNBQVM7Ozs7WUFDNUUsQ0FBQyxhQUFhLEVBQUUsRUFBRTtnQkFDZCxJQUFJLENBQUMsS0FBSyxDQUFDLHVCQUF1QixFQUFFLGFBQWEsQ0FBQyxDQUFDO2dCQUNuRCxJQUFJLENBQUMsd0JBQXdCLENBQ3pCLGFBQWEsQ0FBQyxZQUFZLEVBQzFCLGFBQWEsQ0FBQyxhQUFhLEVBQzNCLGFBQWEsQ0FBQyxVQUFVLEVBQ3hCLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQztnQkFFekIsSUFBSSxJQUFJLENBQUMsSUFBSSxJQUFJLGFBQWEsQ0FBQyxRQUFRLEVBQUU7b0JBQ3JDLElBQUksQ0FBQyxjQUFjLENBQUMsYUFBYSxDQUFDLFFBQVEsRUFBRSxhQUFhLENBQUMsWUFBWSxDQUFDO3dCQUN2RSxJQUFJOzs7O29CQUFDLE1BQU0sQ0FBQyxFQUFFO3dCQUNWLElBQUksQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUM7d0JBRTFCLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksaUJBQWlCLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDO3dCQUNqRSxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLGlCQUFpQixDQUFDLENBQUMsQ0FBQzt3QkFFbEUsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFDO29CQUMzQixDQUFDLEVBQUM7eUJBQ0QsS0FBSzs7OztvQkFBQyxNQUFNLENBQUMsRUFBRTt3QkFDWixJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGVBQWUsQ0FBQyx3QkFBd0IsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDO3dCQUMvRSxPQUFPLENBQUMsS0FBSyxDQUFDLHlCQUF5QixDQUFDLENBQUM7d0JBQ3pDLE9BQU8sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7d0JBRXRCLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQztvQkFDbkIsQ0FBQyxFQUFDLENBQUM7aUJBQ047cUJBQU07b0JBQ0gsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxpQkFBaUIsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLENBQUM7b0JBQ2pFLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksaUJBQWlCLENBQUMsaUJBQWlCLENBQUMsQ0FBQyxDQUFDO29CQUVsRSxPQUFPLENBQUMsYUFBYSxDQUFDLENBQUM7aUJBQzFCO1lBQ0wsQ0FBQzs7OztZQUNELENBQUMsR0FBRyxFQUFFLEVBQUU7Z0JBQ0osT0FBTyxDQUFDLEtBQUssQ0FBQyxxQkFBcUIsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDMUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxlQUFlLENBQUMscUJBQXFCLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDekUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ2hCLENBQUMsRUFDSixDQUFDO1FBQ04sQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7Ozs7Ozs7O0lBVU0sb0JBQW9CLENBQUMsVUFBd0IsSUFBSTtRQUNwRCxPQUFPLEdBQUcsT0FBTyxJQUFJLEVBQUUsQ0FBQzs7WUFFcEIsS0FBYTtRQUVqQixJQUFJLE9BQU8sQ0FBQyxrQkFBa0IsRUFBRTtZQUM1QixLQUFLLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQyxxQkFBcUIsQ0FBQyxPQUFPLENBQUMsa0JBQWtCLENBQUMsQ0FBQztTQUM1RTthQUFNO1lBQ0gsS0FBSyxHQUFHLElBQUksQ0FBQyxTQUFTLENBQUMscUJBQXFCLEVBQUUsQ0FBQztTQUNsRDtRQUVELElBQUksQ0FBQyxLQUFLLENBQUMsWUFBWSxFQUFFLEtBQUssQ0FBQyxDQUFDOztjQUUxQixLQUFLLEdBQUcsS0FBSyxDQUFDLE9BQU8sQ0FBQztZQUV4QixDQUFDLFlBQVksRUFBRSxTQUFTLENBQUMsR0FBRyxJQUFJLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQztRQUN0RCxJQUFJLENBQUMsS0FBSyxHQUFHLFNBQVMsQ0FBQztRQUV2QixJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsRUFBRTtZQUNoQixJQUFJLENBQUMsS0FBSyxDQUFDLHVCQUF1QixDQUFDLENBQUM7WUFDcEMsSUFBSSxDQUFDLGdCQUFnQixDQUFDLE9BQU8sRUFBRSxLQUFLLENBQUMsQ0FBQzs7a0JBQ2hDLEdBQUcsR0FBRyxJQUFJLGVBQWUsQ0FBQyxhQUFhLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQztZQUN6RCxJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUM3QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDOUI7O2NBRUssV0FBVyxHQUFHLEtBQUssQ0FBQyxjQUFjLENBQUM7O2NBQ25DLE9BQU8sR0FBRyxLQUFLLENBQUMsVUFBVSxDQUFDOztjQUMzQixZQUFZLEdBQUcsS0FBSyxDQUFDLGVBQWUsQ0FBQzs7Y0FDckMsYUFBYSxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUM7UUFFcEMsSUFBSSxDQUFDLElBQUksQ0FBQyxrQkFBa0IsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLEVBQUU7WUFDeEMsT0FBTyxPQUFPLENBQUMsTUFBTSxDQUNqQiwyREFBMkQsQ0FDOUQsQ0FBQztTQUNMO1FBRUQsSUFBSSxJQUFJLENBQUMsa0JBQWtCLElBQUksQ0FBQyxXQUFXLEVBQUU7WUFDekMsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ2pDO1FBQ0QsSUFBSSxJQUFJLENBQUMsa0JBQWtCLElBQUksQ0FBQyxPQUFPLENBQUMsdUJBQXVCLElBQUksQ0FBQyxLQUFLLEVBQUU7WUFDdkUsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ2pDO1FBQ0QsSUFBSSxJQUFJLENBQUMsSUFBSSxJQUFJLENBQUMsT0FBTyxFQUFFO1lBQ3ZCLE9BQU8sT0FBTyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUNqQztRQUVELElBQUksSUFBSSxDQUFDLG9CQUFvQixJQUFJLENBQUMsWUFBWSxFQUFFO1lBQzVDLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUNaLHNEQUFzRDtnQkFDdEQsdURBQXVEO2dCQUN2RCx3Q0FBd0MsQ0FDM0MsQ0FBQztTQUNMO1FBRUQsSUFBSSxJQUFJLENBQUMsa0JBQWtCLElBQUksQ0FBQyxPQUFPLENBQUMsdUJBQXVCLEVBQUU7O2tCQUN2RCxPQUFPLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQyxZQUFZLENBQUM7WUFFaEQsSUFBSSxDQUFDLE9BQU8sRUFBRTs7c0JBQ0osS0FBSyxHQUFHLElBQUksZUFBZSxDQUFDLHdCQUF3QixFQUFFLElBQUksQ0FBQztnQkFDakUsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7Z0JBQy9CLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQzthQUNoQztTQUNKO1FBRUQsSUFBSSxJQUFJLENBQUMsa0JBQWtCLEVBQUU7WUFDekIsSUFBSSxDQUFDLHdCQUF3QixDQUN6QixXQUFXLEVBQ1gsSUFBSSxFQUNKLEtBQUssQ0FBQyxZQUFZLENBQUMsSUFBSSxJQUFJLENBQUMsc0NBQXNDLEVBQ2xFLGFBQWEsQ0FDaEIsQ0FBQztTQUNMO1FBRUQsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLEVBQUU7WUFDWixJQUFJLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLGlCQUFpQixDQUFDLGdCQUFnQixDQUFDLENBQUMsQ0FBQztZQUNqRSxJQUFJLElBQUksQ0FBQyxtQkFBbUIsSUFBSSxDQUFDLE9BQU8sQ0FBQywwQkFBMEIsRUFBRTtnQkFDakUsUUFBUSxDQUFDLElBQUksR0FBRyxFQUFFLENBQUM7YUFDdEI7WUFFRCxJQUFJLENBQUMsMkJBQTJCLENBQUMsT0FBTyxDQUFDLENBQUM7WUFDMUMsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO1NBRWhDO1FBRUQsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLE9BQU8sRUFBRSxXQUFXLENBQUM7YUFDM0MsSUFBSTs7OztRQUFDLE1BQU0sQ0FBQyxFQUFFO1lBQ1gsSUFBSSxPQUFPLENBQUMsaUJBQWlCLEVBQUU7Z0JBQzNCLE9BQU8sT0FBTztxQkFDVCxpQkFBaUIsQ0FBQztvQkFDZixXQUFXLEVBQUUsV0FBVztvQkFDeEIsUUFBUSxFQUFFLE1BQU0sQ0FBQyxhQUFhO29CQUM5QixPQUFPLEVBQUUsTUFBTSxDQUFDLE9BQU87b0JBQ3ZCLEtBQUssRUFBRSxLQUFLO2lCQUNmLENBQUM7cUJBQ0QsSUFBSTs7OztnQkFBQyxDQUFDLENBQUMsRUFBRSxDQUFDLE1BQU0sRUFBQyxDQUFDO2FBQzFCO1lBQ0QsT0FBTyxNQUFNLENBQUM7UUFDbEIsQ0FBQyxFQUFDO2FBQ0QsSUFBSTs7OztRQUFDLE1BQU0sQ0FBQyxFQUFFO1lBQ1gsSUFBSSxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUMxQixJQUFJLENBQUMsaUJBQWlCLENBQUMsWUFBWSxDQUFDLENBQUM7WUFDckMsSUFBSSxJQUFJLENBQUMsbUJBQW1CLEVBQUU7Z0JBQzFCLFFBQVEsQ0FBQyxJQUFJLEdBQUcsRUFBRSxDQUFDO2FBQ3RCO1lBQ0QsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxpQkFBaUIsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLENBQUM7WUFDakUsSUFBSSxDQUFDLDJCQUEyQixDQUFDLE9BQU8sQ0FBQyxDQUFDO1lBQzFDLElBQUksQ0FBQyxjQUFjLEdBQUcsS0FBSyxDQUFDO1lBQzVCLE9BQU8sSUFBSSxDQUFDO1FBQ2hCLENBQUMsRUFBQzthQUNELEtBQUs7Ozs7UUFBQyxNQUFNLENBQUMsRUFBRTtZQUNaLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNuQixJQUFJLGVBQWUsQ0FBQyx3QkFBd0IsRUFBRSxNQUFNLENBQUMsQ0FDeEQsQ0FBQztZQUNGLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLHlCQUF5QixDQUFDLENBQUM7WUFDN0MsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDMUIsT0FBTyxPQUFPLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ2xDLENBQUMsRUFBQyxDQUFDO0lBQ1gsQ0FBQzs7Ozs7O0lBRU8sVUFBVSxDQUFDLEtBQWE7O1lBQ3hCLEtBQUssR0FBRyxLQUFLOztZQUNiLFNBQVMsR0FBRyxFQUFFO1FBRWxCLElBQUksS0FBSyxFQUFFOztrQkFDRCxHQUFHLEdBQUcsS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLG1CQUFtQixDQUFDO1lBQzFELElBQUksR0FBRyxHQUFHLENBQUMsQ0FBQyxFQUFFO2dCQUNWLEtBQUssR0FBRyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDN0IsU0FBUyxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUMsR0FBRyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUM7YUFDMUU7U0FDSjtRQUNELE9BQU8sQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFDOUIsQ0FBQzs7Ozs7O0lBRVMsYUFBYSxDQUNuQixZQUFvQjs7Y0FFZCxVQUFVLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDO1FBQ2pELElBQUksVUFBVSxLQUFLLFlBQVksRUFBRTs7a0JBRXZCLEdBQUcsR0FBRyxvREFBb0Q7WUFDaEUsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsVUFBVSxFQUFFLFlBQVksQ0FBQyxDQUFDO1lBQzdDLE9BQU8sS0FBSyxDQUFDO1NBQ2hCO1FBQ0QsT0FBTyxJQUFJLENBQUM7SUFDaEIsQ0FBQzs7Ozs7O0lBRVMsWUFBWSxDQUFDLE9BQXNCO1FBQ3pDLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDbkQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLEVBQUUsT0FBTyxDQUFDLGlCQUFpQixDQUFDLENBQUM7UUFDeEUsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLEVBQUUsRUFBRSxHQUFHLE9BQU8sQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1FBQzVFLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLG9CQUFvQixFQUFFLEVBQUUsR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQztJQUNqRSxDQUFDOzs7Ozs7SUFFUyxpQkFBaUIsQ0FBQyxZQUFvQjtRQUM1QyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxlQUFlLEVBQUUsWUFBWSxDQUFDLENBQUM7SUFDekQsQ0FBQzs7Ozs7SUFFUyxlQUFlO1FBQ3JCLE9BQU8sSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsZUFBZSxDQUFDLENBQUM7SUFDbEQsQ0FBQzs7Ozs7OztJQUVTLGdCQUFnQixDQUFDLE9BQXFCLEVBQUUsS0FBYTtRQUMzRCxJQUFJLE9BQU8sQ0FBQyxZQUFZLEVBQUU7WUFDdEIsT0FBTyxDQUFDLFlBQVksQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUMvQjtRQUNELElBQUksSUFBSSxDQUFDLG1CQUFtQixFQUFFO1lBQzFCLFFBQVEsQ0FBQyxJQUFJLEdBQUcsRUFBRSxDQUFDO1NBQ3RCO0lBQ0wsQ0FBQzs7Ozs7Ozs7SUFLTSxjQUFjLENBQ2pCLE9BQWUsRUFDZixXQUFtQixFQUNuQixjQUFjLEdBQUcsS0FBSzs7Y0FFaEIsVUFBVSxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDOztjQUMvQixZQUFZLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUM7O2NBQzVDLFVBQVUsR0FBRyxnQkFBZ0IsQ0FBQyxZQUFZLENBQUM7O2NBQzNDLE1BQU0sR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQzs7Y0FDL0IsWUFBWSxHQUFHLElBQUksQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDOztjQUM1QyxVQUFVLEdBQUcsZ0JBQWdCLENBQUMsWUFBWSxDQUFDOztjQUMzQyxNQUFNLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUM7O2NBQy9CLFVBQVUsR0FBRyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUM7UUFFakQsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsRUFBRTtZQUMzQixJQUFJLE1BQU0sQ0FBQyxHQUFHLENBQUMsS0FBSzs7OztZQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLLElBQUksQ0FBQyxRQUFRLEVBQUMsRUFBRTs7c0JBQ3RDLEdBQUcsR0FBRyxrQkFBa0IsR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQ3JELElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUN0QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7YUFDOUI7U0FDSjthQUFNO1lBQ0gsSUFBSSxNQUFNLENBQUMsR0FBRyxLQUFLLElBQUksQ0FBQyxRQUFRLEVBQUU7O3NCQUN4QixHQUFHLEdBQUcsa0JBQWtCLEdBQUcsTUFBTSxDQUFDLEdBQUc7Z0JBQzNDLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUN0QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7YUFDOUI7U0FDSjtRQUVELElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFFOztrQkFDUCxHQUFHLEdBQUcsMEJBQTBCO1lBQ3RDLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ3RCLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUM5QjtRQUVEOzs7O1dBSUc7UUFDSCxJQUNJLElBQUksQ0FBQyxvQkFBb0I7WUFDekIsSUFBSSxDQUFDLG9CQUFvQjtZQUN6QixJQUFJLENBQUMsb0JBQW9CLEtBQUssTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUM3Qzs7a0JBQ1EsR0FBRyxHQUNMLCtEQUErRDtnQkFDL0QsaUJBQWlCLElBQUksQ0FBQyxvQkFBb0IsbUJBQzFDLE1BQU0sQ0FBQyxLQUFLLENBQ1osRUFBRTtZQUVOLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ3RCLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUM5QjtRQUVELElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFFOztrQkFDUCxHQUFHLEdBQUcsMEJBQTBCO1lBQ3RDLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ3RCLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUM5QjtRQUVELElBQUksQ0FBQyxJQUFJLENBQUMsZUFBZSxJQUFJLE1BQU0sQ0FBQyxHQUFHLEtBQUssSUFBSSxDQUFDLE1BQU0sRUFBRTs7a0JBQy9DLEdBQUcsR0FBRyxnQkFBZ0IsR0FBRyxNQUFNLENBQUMsR0FBRztZQUN6QyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUN0QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDOUI7UUFFRCxJQUFJLENBQUMsY0FBYyxJQUFJLE1BQU0sQ0FBQyxLQUFLLEtBQUssVUFBVSxFQUFFOztrQkFDMUMsR0FBRyxHQUFHLGVBQWUsR0FBRyxNQUFNLENBQUMsS0FBSztZQUMxQyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUN0QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDOUI7UUFFRCxJQUNJLENBQUMsSUFBSSxDQUFDLGtCQUFrQjtZQUN4QixJQUFJLENBQUMsa0JBQWtCO1lBQ3ZCLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxFQUNwQjs7a0JBQ1EsR0FBRyxHQUFHLHVCQUF1QjtZQUNuQyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUN0QixPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDOUI7O2NBRUssR0FBRyxHQUFHLElBQUksQ0FBQyxHQUFHLEVBQUU7O2NBQ2hCLFlBQVksR0FBRyxNQUFNLENBQUMsR0FBRyxHQUFHLElBQUk7O2NBQ2hDLGFBQWEsR0FBRyxNQUFNLENBQUMsR0FBRyxHQUFHLElBQUk7O2NBQ2pDLGVBQWUsR0FBRyxDQUFDLElBQUksQ0FBQyxjQUFjLElBQUksR0FBRyxDQUFDLEdBQUcsSUFBSTtRQUUzRCxJQUNJLFlBQVksR0FBRyxlQUFlLElBQUksR0FBRztZQUNyQyxhQUFhLEdBQUcsZUFBZSxJQUFJLEdBQUcsRUFDeEM7O2tCQUNRLEdBQUcsR0FBRyxtQkFBbUI7WUFDL0IsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNuQixPQUFPLENBQUMsS0FBSyxDQUFDO2dCQUNWLEdBQUcsRUFBRSxHQUFHO2dCQUNSLFlBQVksRUFBRSxZQUFZO2dCQUMxQixhQUFhLEVBQUUsYUFBYTthQUMvQixDQUFDLENBQUM7WUFDSCxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDOUI7O2NBRUssZ0JBQWdCLEdBQXFCO1lBQ3ZDLFdBQVcsRUFBRSxXQUFXO1lBQ3hCLE9BQU8sRUFBRSxPQUFPO1lBQ2hCLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSTtZQUNmLGFBQWEsRUFBRSxNQUFNO1lBQ3JCLGFBQWEsRUFBRSxNQUFNO1lBQ3JCLFFBQVE7OztZQUFFLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQTtTQUNsQztRQUdELE9BQU8sSUFBSSxDQUFDLFdBQVcsQ0FBQyxnQkFBZ0IsQ0FBQzthQUN0QyxJQUFJOzs7O1FBQUMsV0FBVyxDQUFDLEVBQUU7WUFDbEIsSUFDRSxDQUFDLElBQUksQ0FBQyxrQkFBa0I7Z0JBQ3hCLElBQUksQ0FBQyxrQkFBa0I7Z0JBQ3ZCLENBQUMsV0FBVyxFQUNkOztzQkFDUSxHQUFHLEdBQUcsZUFBZTtnQkFDM0IsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBQ3RCLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQzthQUM5QjtZQUVELE9BQU8sSUFBSSxDQUFDLGNBQWMsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLElBQUk7Ozs7WUFBQyxDQUFDLENBQUMsRUFBRTs7c0JBQzVDLE1BQU0sR0FBa0I7b0JBQzFCLE9BQU8sRUFBRSxPQUFPO29CQUNoQixhQUFhLEVBQUUsTUFBTTtvQkFDckIsaUJBQWlCLEVBQUUsVUFBVTtvQkFDN0IsYUFBYSxFQUFFLE1BQU07b0JBQ3JCLGlCQUFpQixFQUFFLFVBQVU7b0JBQzdCLGdCQUFnQixFQUFFLGFBQWE7aUJBQ2xDO2dCQUNELE9BQU8sTUFBTSxDQUFDO1lBQ2xCLENBQUMsRUFBQyxDQUFDO1FBRUwsQ0FBQyxFQUFDLENBQUM7SUFDUCxDQUFDOzs7OztJQUtNLGlCQUFpQjs7Y0FDZCxNQUFNLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLENBQUM7UUFDM0QsSUFBSSxDQUFDLE1BQU0sRUFBRTtZQUNULE9BQU8sSUFBSSxDQUFDO1NBQ2Y7UUFDRCxPQUFPLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDOUIsQ0FBQzs7Ozs7SUFLTSxnQkFBZ0I7O2NBQ2IsTUFBTSxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGdCQUFnQixDQUFDO1FBQ3RELElBQUksQ0FBQyxNQUFNLEVBQUU7WUFDVCxPQUFPLElBQUksQ0FBQztTQUNmO1FBQ0QsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBQzlCLENBQUM7Ozs7O0lBS00sVUFBVTtRQUNiLE9BQU8sSUFBSSxDQUFDLFFBQVE7WUFDaEIsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQztZQUNuQyxDQUFDLENBQUMsSUFBSSxDQUFDO0lBQ2YsQ0FBQzs7Ozs7O0lBRVMsU0FBUyxDQUFDLFVBQVU7UUFDMUIsT0FBTyxVQUFVLENBQUMsTUFBTSxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDaEMsVUFBVSxJQUFJLEdBQUcsQ0FBQztTQUNyQjtRQUNELE9BQU8sVUFBVSxDQUFDO0lBQ3RCLENBQUM7Ozs7O0lBS00sY0FBYztRQUNqQixPQUFPLElBQUksQ0FBQyxRQUFRO1lBQ2hCLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxjQUFjLENBQUM7WUFDdkMsQ0FBQyxDQUFDLElBQUksQ0FBQztJQUNmLENBQUM7Ozs7SUFFTSxlQUFlO1FBQ2xCLE9BQU8sSUFBSSxDQUFDLFFBQVE7WUFDaEIsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLGVBQWUsQ0FBQztZQUN4QyxDQUFDLENBQUMsSUFBSSxDQUFDO0lBQ2YsQ0FBQzs7Ozs7O0lBTU0sd0JBQXdCO1FBQzNCLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsRUFBRTtZQUN0QyxPQUFPLElBQUksQ0FBQztTQUNmO1FBQ0QsT0FBTyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUM7SUFDN0QsQ0FBQzs7Ozs7SUFFUyxzQkFBc0I7UUFDNUIsT0FBTyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsd0JBQXdCLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQztJQUN6RSxDQUFDOzs7OztJQUVTLGtCQUFrQjtRQUN4QixPQUFPLFFBQVEsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBQ3JFLENBQUM7Ozs7OztJQU1NLG9CQUFvQjtRQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLENBQUMsRUFBRTtZQUMvQyxPQUFPLElBQUksQ0FBQztTQUNmO1FBRUQsT0FBTyxRQUFRLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMscUJBQXFCLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQztJQUN0RSxDQUFDOzs7OztJQUtNLG1CQUFtQjtRQUN0QixJQUFJLElBQUksQ0FBQyxjQUFjLEVBQUUsRUFBRTs7a0JBQ2pCLFNBQVMsR0FBRyxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUM7O2tCQUMvQyxHQUFHLEdBQUcsSUFBSSxJQUFJLEVBQUU7WUFDdEIsSUFBSSxTQUFTLElBQUksUUFBUSxDQUFDLFNBQVMsRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFHLENBQUMsT0FBTyxFQUFFLEVBQUU7Z0JBQ3RELE9BQU8sS0FBSyxDQUFDO2FBQ2hCO1lBRUQsT0FBTyxJQUFJLENBQUM7U0FDZjtRQUVELE9BQU8sS0FBSyxDQUFDO0lBQ2pCLENBQUM7Ozs7O0lBS00sZUFBZTtRQUNsQixJQUFJLElBQUksQ0FBQyxVQUFVLEVBQUUsRUFBRTs7a0JBQ2IsU0FBUyxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLHFCQUFxQixDQUFDOztrQkFDeEQsR0FBRyxHQUFHLElBQUksSUFBSSxFQUFFO1lBQ3RCLElBQUksU0FBUyxJQUFJLFFBQVEsQ0FBQyxTQUFTLEVBQUUsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDLE9BQU8sRUFBRSxFQUFFO2dCQUN0RCxPQUFPLEtBQUssQ0FBQzthQUNoQjtZQUVELE9BQU8sSUFBSSxDQUFDO1NBQ2Y7UUFFRCxPQUFPLEtBQUssQ0FBQztJQUNqQixDQUFDOzs7Ozs7SUFNTSxtQkFBbUI7UUFDdEIsT0FBTyxTQUFTLEdBQUcsSUFBSSxDQUFDLGNBQWMsRUFBRSxDQUFDO0lBQzdDLENBQUM7Ozs7Ozs7O0lBUU0sTUFBTSxDQUFDLHFCQUFxQixHQUFHLEtBQUs7O2NBQ2pDLFFBQVEsR0FBRyxJQUFJLENBQUMsVUFBVSxFQUFFO1FBQ2xDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLGNBQWMsQ0FBQyxDQUFDO1FBQ3pDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLFVBQVUsQ0FBQyxDQUFDO1FBQ3JDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLGVBQWUsQ0FBQyxDQUFDO1FBQzFDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ2xDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLFlBQVksQ0FBQyxDQUFDO1FBQ3ZDLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLHFCQUFxQixDQUFDLENBQUM7UUFDaEQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxVQUFVLENBQUMscUJBQXFCLENBQUMsQ0FBQztRQUNoRCxJQUFJLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO1FBQy9DLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLHdCQUF3QixDQUFDLENBQUM7UUFDbkQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxVQUFVLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztRQUMzQyxJQUFJLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxlQUFlLENBQUMsQ0FBQztRQUUxQyxJQUFJLENBQUMsb0JBQW9CLEdBQUcsSUFBSSxDQUFDO1FBRWpDLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksY0FBYyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUM7UUFFdEQsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUU7WUFDakIsT0FBTztTQUNWO1FBQ0QsSUFBSSxxQkFBcUIsRUFBRTtZQUN2QixPQUFPO1NBQ1Y7UUFFRCxJQUFJLENBQUMsUUFBUSxJQUFJLENBQUMsSUFBSSxDQUFDLHFCQUFxQixFQUFFO1lBQzFDLE9BQU87U0FDVjs7WUFFRyxTQUFpQjtRQUVyQixJQUFJLENBQUMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsRUFBRTtZQUMzQyxNQUFNLElBQUksS0FBSyxDQUNYLHFGQUFxRixDQUN4RixDQUFDO1NBQ0w7UUFFRCw2QkFBNkI7UUFDN0IsSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRTtZQUNuQyxTQUFTLEdBQUcsSUFBSSxDQUFDLFNBQVM7aUJBQ3JCLE9BQU8sQ0FBQyxrQkFBa0IsRUFBRSxRQUFRLENBQUM7aUJBQ3JDLE9BQU8sQ0FBQyxtQkFBbUIsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7U0FDcEQ7YUFBTTs7Z0JBRUMsTUFBTSxHQUFHLElBQUksVUFBVSxFQUFFO1lBRTdCLElBQUksUUFBUSxFQUFFO2dCQUNWLE1BQU0sR0FBRyxNQUFNLENBQUMsR0FBRyxDQUFDLGVBQWUsRUFBRSxRQUFRLENBQUMsQ0FBQzthQUNsRDs7a0JBRUssYUFBYSxHQUFHLElBQUksQ0FBQyxxQkFBcUIsSUFBSSxJQUFJLENBQUMsV0FBVztZQUNwRSxJQUFJLGFBQWEsRUFBRTtnQkFDZixNQUFNLEdBQUcsTUFBTSxDQUFDLEdBQUcsQ0FBQywwQkFBMEIsRUFBRSxhQUFhLENBQUMsQ0FBQzthQUNsRTtZQUVELFNBQVM7Z0JBQ0wsSUFBSSxDQUFDLFNBQVM7b0JBQ2QsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUM7b0JBQzlDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsQ0FBQztTQUN6QjtRQUNELElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLFNBQVMsQ0FBQyxDQUFDO0lBQ25DLENBQUM7Ozs7O0lBS00sa0JBQWtCOztjQUNmLElBQUksR0FBRyxJQUFJO1FBQ2pCLE9BQU8sSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDLElBQUk7Ozs7UUFBQyxVQUFVLEtBQVU7WUFDL0MsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLEtBQUssQ0FBQyxDQUFDO1lBQ3RDLE9BQU8sS0FBSyxDQUFDO1FBQ2pCLENBQUMsRUFBQyxDQUFDO0lBQ1AsQ0FBQzs7Ozs7SUFLTSxXQUFXO1FBQ2QsSUFBSSxDQUFDLHFCQUFxQixFQUFFLENBQUM7UUFDN0IsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7SUFDN0IsQ0FBQzs7Ozs7SUFFUyxXQUFXO1FBQ2pCLE9BQU8sSUFBSSxPQUFPOzs7O1FBQUMsQ0FBQyxPQUFPLEVBQUUsRUFBRTtZQUMzQixJQUFJLElBQUksQ0FBQyxNQUFNLEVBQUU7Z0JBQ2IsTUFBTSxJQUFJLEtBQUssQ0FDWCw4REFBOEQsQ0FDakUsQ0FBQzthQUNMOzs7Ozs7a0JBTUssR0FBRyxHQUFHLGtFQUFrRTs7Z0JBQzFFLElBQUksR0FBRyxFQUFFOztnQkFDVCxFQUFFLEdBQUcsRUFBRTs7a0JBRUwsTUFBTSxHQUFHLElBQUksQ0FBQyxNQUFNLElBQUksSUFBSSxDQUFDLFVBQVUsQ0FBQztZQUM5QyxJQUFJLE1BQU0sRUFBRTs7c0JBQ0YsS0FBSyxHQUFHLE1BQU0sQ0FBQyxlQUFlLENBQUMsSUFBSSxVQUFVLENBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQzFELE9BQU8sQ0FBQyxHQUFHLElBQUksRUFBRSxFQUFFO29CQUNmLEVBQUUsSUFBSSxHQUFHLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFDO2lCQUMvQjthQUNKO2lCQUFNO2dCQUNILE9BQU8sQ0FBQyxHQUFHLElBQUksRUFBRSxFQUFFO29CQUNmLEVBQUUsSUFBSSxHQUFHLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQztpQkFDckM7YUFDSjtZQUVELE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUNoQixDQUFDLEVBQUMsQ0FBQztJQUNQLENBQUM7Ozs7OztJQUVlLFdBQVcsQ0FBQyxNQUF3Qjs7WUFDaEQsSUFBSSxDQUFDLElBQUksQ0FBQyxzQkFBc0IsRUFBRTtnQkFDOUIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQ1osNkRBQTZELENBQ2hFLENBQUM7Z0JBQ0YsT0FBTyxJQUFJLENBQUM7YUFDZjtZQUNELE9BQU8sSUFBSSxDQUFDLHNCQUFzQixDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUM5RCxDQUFDO0tBQUE7Ozs7OztJQUVTLGNBQWMsQ0FBQyxNQUF3QjtRQUM3QyxJQUFJLENBQUMsSUFBSSxDQUFDLHNCQUFzQixFQUFFO1lBQzlCLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUNaLCtEQUErRCxDQUNsRSxDQUFDO1lBQ0YsT0FBTyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO1NBQ2hDO1FBQ0QsT0FBTyxJQUFJLENBQUMsc0JBQXNCLENBQUMsaUJBQWlCLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDakUsQ0FBQzs7Ozs7Ozs7SUFPTSxhQUFhLENBQ2hCLGVBQWUsR0FBRyxFQUFFLEVBQ3BCLE1BQU0sR0FBRyxFQUFFO1FBRVgsSUFBSSxJQUFJLENBQUMsWUFBWSxLQUFLLE1BQU0sRUFBRTtZQUM5QixPQUFPLElBQUksQ0FBQyxZQUFZLENBQUMsZUFBZSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1NBQ3JEO2FBQU07WUFDSCxPQUFPLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxlQUFlLEVBQUUsTUFBTSxDQUFDLENBQUM7U0FDekQ7SUFDTCxDQUFDOzs7Ozs7OztJQU1NLFlBQVksQ0FDZixlQUFlLEdBQUcsRUFBRSxFQUNwQixNQUFNLEdBQUcsRUFBRTtRQUVYLElBQUksSUFBSSxDQUFDLFFBQVEsS0FBSyxFQUFFLEVBQUU7WUFDdEIsSUFBSSxDQUFDLG9CQUFvQixDQUFDLGVBQWUsRUFBRSxNQUFNLENBQUMsQ0FBQztTQUN0RDthQUFNO1lBQ0gsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTs7OztZQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSywyQkFBMkIsRUFBQyxDQUFDO2lCQUNwRSxTQUFTOzs7O1lBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsb0JBQW9CLENBQUMsZUFBZSxFQUFFLE1BQU0sQ0FBQyxFQUFDLENBQUM7U0FDdkU7SUFDTCxDQUFDOzs7Ozs7O0lBRU8sb0JBQW9CLENBQ3hCLGVBQWUsR0FBRyxFQUFFLEVBQ3BCLE1BQU0sR0FBRyxFQUFFO1FBR1gsSUFBSSxDQUFDLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLEVBQUU7WUFDMUMsTUFBTSxJQUFJLEtBQUssQ0FBQywyREFBMkQsQ0FBQyxDQUFDO1NBQ2hGO1FBRUQsSUFBSSxDQUFDLGNBQWMsQ0FBQyxlQUFlLEVBQUUsRUFBRSxFQUFFLElBQUksRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsS0FBSzs7OztRQUFDLEtBQUssQ0FBQyxFQUFFO1lBQ2xHLE9BQU8sQ0FBQyxLQUFLLENBQUMsb0NBQW9DLENBQUMsQ0FBQztZQUNwRCxPQUFPLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3pCLENBQUMsRUFBQyxDQUFDO0lBRVAsQ0FBQzs7Ozs7SUFFZSxrQ0FBa0M7O1lBRTlDLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFO2dCQUNkLE1BQU0sSUFBSSxLQUFLLENBQUMsbUdBQW1HLENBQUMsQ0FBQzthQUN4SDs7a0JBR0ssUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsRUFBRTs7a0JBQ25DLFlBQVksR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRSxTQUFTLENBQUM7O2tCQUM5RCxTQUFTLEdBQUcsZUFBZSxDQUFDLFlBQVksQ0FBQztZQUUvQyxPQUFPLENBQUMsU0FBUyxFQUFFLFFBQVEsQ0FBQyxDQUFDO1FBQ2pDLENBQUM7S0FBQTs7O1lBMW1FSixVQUFVOzs7O1lBbkNVLE1BQU07WUFDbEIsVUFBVTtZQWlCZixZQUFZLHVCQW9FUCxRQUFRO1lBaEZiLGlCQUFpQix1QkFpRlosUUFBUTtZQTdEUixVQUFVLHVCQThEVixRQUFRO1lBL0VSLGdCQUFnQjtZQVFyQixXQUFXO1lBV04sYUFBYSx1QkErRGIsUUFBUTs7Ozs7Ozs7SUEvQ2IsOENBQWlEOzs7Ozs7SUFNakQsK0NBQXVDOzs7Ozs7SUFNdkMsZ0RBQW9EOzs7Ozs7SUFNcEQsOEJBQXNDOzs7Ozs7SUFNdEMsNkJBQW1COzs7OztJQUVuQixxQ0FBeUU7Ozs7O0lBQ3pFLHNEQUFrRjs7Ozs7SUFDbEYsNkRBQStEOzs7OztJQUMvRCwyQ0FBa0Q7Ozs7O0lBQ2xELGdDQUFpQzs7Ozs7SUFDakMsc0RBQXVEOzs7OztJQUN2RCxrREFBbUQ7Ozs7O0lBQ25ELGlEQUFtRDs7Ozs7SUFDbkQsK0JBQTBCOzs7OztJQUMxQix5Q0FBaUM7Ozs7O0lBQ2pDLDRDQUF1Qzs7Ozs7SUFDdkMsc0NBQWlDOzs7OztJQUc3Qiw4QkFBd0I7Ozs7O0lBQ3hCLDRCQUEwQjs7Ozs7SUFHMUIsOEJBQXdDOzs7OztJQUN4QyxpQ0FBcUM7Ozs7O0lBQ3JDLDhCQUE2Qjs7Ozs7SUFDN0IsOEJBQTJDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lLCBPcHRpb25hbCwgT25EZXN0cm95IH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBIdHRwQ2xpZW50LCBIdHRwSGVhZGVycywgSHR0cFBhcmFtcyB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIFN1YmplY3QsIFN1YnNjcmlwdGlvbiwgb2YsIHJhY2UsIGZyb20gfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGZpbHRlciwgZGVsYXksIGZpcnN0LCB0YXAsIG1hcCwgc3dpdGNoTWFwIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuXG5pbXBvcnQge1xuICAgIFZhbGlkYXRpb25IYW5kbGVyLFxuICAgIFZhbGlkYXRpb25QYXJhbXNcbn0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuaW1wb3J0IHtcbiAgICBPQXV0aEV2ZW50LFxuICAgIE9BdXRoSW5mb0V2ZW50LFxuICAgIE9BdXRoRXJyb3JFdmVudCxcbiAgICBPQXV0aFN1Y2Nlc3NFdmVudFxufSBmcm9tICcuL2V2ZW50cyc7XG5pbXBvcnQge1xuICAgIE9BdXRoTG9nZ2VyLFxuICAgIE9BdXRoU3RvcmFnZSxcbiAgICBMb2dpbk9wdGlvbnMsXG4gICAgUGFyc2VkSWRUb2tlbixcbiAgICBPaWRjRGlzY292ZXJ5RG9jLFxuICAgIFRva2VuUmVzcG9uc2UsXG4gICAgVXNlckluZm9cbn0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBiNjREZWNvZGVVbmljb2RlLCBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuL2Jhc2U2NC1oZWxwZXInO1xuaW1wb3J0IHsgQXV0aENvbmZpZyB9IGZyb20gJy4vYXV0aC5jb25maWcnO1xuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xuaW1wb3J0IHsgQ3J5cHRvSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9jcnlwdG8taGFuZGxlcic7XG5cbi8qKlxuICogU2VydmljZSBmb3IgbG9nZ2luZyBpbiBhbmQgbG9nZ2luZyBvdXQgd2l0aFxuICogT0lEQyBhbmQgT0F1dGgyLiBTdXBwb3J0cyBpbXBsaWNpdCBmbG93IGFuZFxuICogcGFzc3dvcmQgZmxvdy5cbiAqL1xuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIE9BdXRoU2VydmljZSBleHRlbmRzIEF1dGhDb25maWcgaW1wbGVtZW50cyBPbkRlc3Ryb3kge1xuICAgIC8vIEV4dGVuZGluZyBBdXRoQ29uZmlnIGlzdCBqdXN0IGZvciBMRUdBQ1kgcmVhc29uc1xuICAgIC8vIHRvIG5vdCBicmVhayBleGlzdGluZyBjb2RlLlxuXG4gICAgLyoqXG4gICAgICogVGhlIFZhbGlkYXRpb25IYW5kbGVyIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWRcbiAgICAgKiBpZF90b2tlbnMuXG4gICAgICovXG4gICAgcHVibGljIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyO1xuXG4gICAgLyoqXG4gICAgICogQGludGVybmFsXG4gICAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxuICAgICAqL1xuICAgIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IGZhbHNlO1xuXG4gICAgLyoqXG4gICAgICogQGludGVybmFsXG4gICAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxuICAgICAqL1xuICAgIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQ6IE9ic2VydmFibGU8b2JqZWN0PjtcblxuICAgIC8qKlxuICAgICAqIEluZm9ybXMgYWJvdXQgZXZlbnRzLCBsaWtlIHRva2VuX3JlY2VpdmVkIG9yIHRva2VuX2V4cGlyZXMuXG4gICAgICogU2VlIHRoZSBzdHJpbmcgZW51bSBFdmVudFR5cGUgZm9yIGEgZnVsbCBsaXN0IG9mIGV2ZW50IHR5cGVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBldmVudHM6IE9ic2VydmFibGU8T0F1dGhFdmVudD47XG5cbiAgICAvKipcbiAgICAgKiBUaGUgcmVjZWl2ZWQgKHBhc3NlZCBhcm91bmQpIHN0YXRlLCB3aGVuIGxvZ2dpbmdcbiAgICAgKiBpbiB3aXRoIGltcGxpY2l0IGZsb3cuXG4gICAgICovXG4gICAgcHVibGljIHN0YXRlPyA9ICcnO1xuXG4gICAgcHJvdGVjdGVkIGV2ZW50c1N1YmplY3Q6IFN1YmplY3Q8T0F1dGhFdmVudD4gPSBuZXcgU3ViamVjdDxPQXV0aEV2ZW50PigpO1xuICAgIHByb3RlY3RlZCBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3Q6IFN1YmplY3Q8b2JqZWN0PiA9IG5ldyBTdWJqZWN0PG9iamVjdD4oKTtcbiAgICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgICBwcm90ZWN0ZWQgZ3JhbnRUeXBlc1N1cHBvcnRlZDogQXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgIHByb3RlY3RlZCBfc3RvcmFnZTogT0F1dGhTdG9yYWdlO1xuICAgIHByb3RlY3RlZCBhY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgICBwcm90ZWN0ZWQgaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xuICAgIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xuICAgIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoU3ViamVjdDogc3RyaW5nO1xuICAgIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuXG4gICAgY29uc3RydWN0b3IoXG4gICAgICAgIHByb3RlY3RlZCBuZ1pvbmU6IE5nWm9uZSxcbiAgICAgICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXG4gICAgICAgIEBPcHRpb25hbCgpIHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSxcbiAgICAgICAgQE9wdGlvbmFsKCkgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXIsXG4gICAgICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXG4gICAgICAgIHByb3RlY3RlZCB1cmxIZWxwZXI6IFVybEhlbHBlclNlcnZpY2UsXG4gICAgICAgIHByb3RlY3RlZCBsb2dnZXI6IE9BdXRoTG9nZ2VyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBDcnlwdG9IYW5kbGVyLFxuICAgICkge1xuICAgICAgICBzdXBlcigpO1xuXG4gICAgICAgIHRoaXMuZGVidWcoJ2FuZ3VsYXItb2F1dGgyLW9pZGMgdjgtYmV0YScpO1xuXG4gICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkID0gdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QuYXNPYnNlcnZhYmxlKCk7XG4gICAgICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuXG4gICAgICAgIGlmICh0b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgICB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIgPSB0b2tlblZhbGlkYXRpb25IYW5kbGVyO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNvbmZpZykge1xuICAgICAgICAgICAgdGhpcy5jb25maWd1cmUoY29uZmlnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAoc3RvcmFnZSkge1xuICAgICAgICAgICAgICAgIHRoaXMuc2V0U3RvcmFnZShzdG9yYWdlKTtcbiAgICAgICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHNlc3Npb25TdG9yYWdlICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgICAgIHRoaXMuc2V0U3RvcmFnZShzZXNzaW9uU3RvcmFnZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGUpIHtcblxuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcbiAgICAgICAgICAgICAgICAnTm8gT0F1dGhTdG9yYWdlIHByb3ZpZGVkIGFuZCBjYW5ub3QgYWNjZXNzIGRlZmF1bHQgKHNlc3Npb25TdG9yYWdlKS4nXG4gICAgICAgICAgICAgICAgKyAnQ29uc2lkZXIgcHJvdmlkaW5nIGEgY3VzdG9tIE9BdXRoU3RvcmFnZSBpbXBsZW1lbnRhdGlvbiBpbiB5b3VyIG1vZHVsZS4nLFxuICAgICAgICAgICAgICAgIGVcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGNvbmZpZ3VyZSB0aGUgc2VydmljZVxuICAgICAqIEBwYXJhbSBjb25maWcgdGhlIGNvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgY29uZmlndXJlKGNvbmZpZzogQXV0aENvbmZpZykge1xuICAgICAgICAvLyBGb3IgdGhlIHNha2Ugb2YgZG93bndhcmQgY29tcGF0aWJpbGl0eSB3aXRoXG4gICAgICAgIC8vIG9yaWdpbmFsIGNvbmZpZ3VyYXRpb24gQVBJXG4gICAgICAgIE9iamVjdC5hc3NpZ24odGhpcywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgICAgICB0aGlzLmNvbmZpZyA9IE9iamVjdC5hc3NpZ24oe30gYXMgQXV0aENvbmZpZywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVjaygpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNvbmZpZ0NoYW5nZWQoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgcmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCByZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVjaygpIHtcbiAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogV2lsbCBzZXR1cCB1cCBzaWxlbnQgcmVmcmVzaGluZyBmb3Igd2hlbiB0aGUgdG9rZW4gaXNcbiAgICAgKiBhYm91dCB0byBleHBpcmUuIFdoZW4gdGhlIHVzZXIgaXMgbG9nZ2VkIG91dCB2aWEgdGhpcy5sb2dPdXQgbWV0aG9kLCB0aGVcbiAgICAgKiBzaWxlbnQgcmVmcmVzaGluZyB3aWxsIHBhdXNlIGFuZCBub3QgcmVmcmVzaCB0aGUgdG9rZW5zIHVudGlsIHRoZSB1c2VyIGlzXG4gICAgICogbG9nZ2VkIGJhY2sgaW4gdmlhIHJlY2VpdmluZyBhIG5ldyB0b2tlbi5cbiAgICAgKiBAcGFyYW0gcGFyYW1zIEFkZGl0aW9uYWwgcGFyYW1ldGVyIHRvIHBhc3NcbiAgICAgKiBAcGFyYW0gbGlzdGVuVG8gU2V0dXAgYXV0b21hdGljIHJlZnJlc2ggb2YgYSBzcGVjaWZpYyB0b2tlbiB0eXBlXG4gICAgICovXG4gICAgcHVibGljIHNldHVwQXV0b21hdGljU2lsZW50UmVmcmVzaChwYXJhbXM6IG9iamVjdCA9IHt9LCBsaXN0ZW5Ubz86ICdhY2Nlc3NfdG9rZW4nIHwgJ2lkX3Rva2VuJyB8ICdhbnknLCBub1Byb21wdCA9IHRydWUpIHtcbiAgICAgIGxldCBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcbiAgICAgIHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgIHRhcCgoZSkgPT4ge1xuICAgICAgICAgIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAnbG9nb3V0Jykge1xuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgfSksXG4gICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX2V4cGlyZXMnKVxuICAgICAgKS5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgIGNvbnN0IGV2ZW50ID0gZSBhcyBPQXV0aEluZm9FdmVudDtcbiAgICAgICAgaWYgKChsaXN0ZW5UbyA9PSBudWxsIHx8IGxpc3RlblRvID09PSAnYW55JyB8fCBldmVudC5pbmZvID09PSBsaXN0ZW5UbykgJiYgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCkge1xuICAgICAgICAgIC8vIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcbiAgICAgICAgICB0aGlzLnJlZnJlc2hJbnRlcm5hbChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ0F1dG9tYXRpYyBzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsnKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICAgIHRoaXMucmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkge1xuICAgICAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFRva2VuKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudCguLi4pYCBhbmRcbiAgICAgKiBkaXJlY3RseSBjaGFpbnMgdXNpbmcgdGhlIGB0aGVuKC4uLilgIHBhcnQgb2YgdGhlIHByb21pc2UgdG8gY2FsbFxuICAgICAqIHRoZSBgdHJ5TG9naW4oLi4uKWAgbWV0aG9kLlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnQoKS50aGVuKGRvYyA9PiB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbihvcHRpb25zKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKC4uLilgXG4gICAgICogYW5kIGlmIHRoZW4gY2hhaW5zIHRvIGBpbml0SW1wbGljaXRGbG93KClgLCBidXQgb25seSBpZiB0aGVyZSBpcyBubyB2YWxpZFxuICAgICAqIElkVG9rZW4gb3Igbm8gdmFsaWQgQWNjZXNzVG9rZW4uXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICBpZiAoIXRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93KCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGRlYnVnKC4uLmFyZ3MpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmRlYnVnLmFwcGx5KGNvbnNvbGUsIGFyZ3MpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KHVybDogc3RyaW5nKTogc3RyaW5nW10ge1xuICAgICAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XG4gICAgICAgIGNvbnN0IGh0dHBzQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKTtcbiAgICAgICAgY29uc3QgaXNzdWVyQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmwpO1xuXG4gICAgICAgIGlmICghaHR0cHNDaGVjaykge1xuICAgICAgICAgICAgZXJyb3JzLnB1c2goXG4gICAgICAgICAgICAgICAgJ2h0dHBzIGZvciBhbGwgdXJscyByZXF1aXJlZC4gQWxzbyBmb3IgdXJscyByZWNlaXZlZCBieSBkaXNjb3ZlcnkuJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaXNzdWVyQ2hlY2spIHtcbiAgICAgICAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAgICAgICAgICdFdmVyeSB1cmwgaW4gZGlzY292ZXJ5IGRvY3VtZW50IGhhcyB0byBzdGFydCB3aXRoIHRoZSBpc3N1ZXIgdXJsLicgK1xuICAgICAgICAgICAgICAgICdBbHNvIHNlZSBwcm9wZXJ0eSBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24uJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBlcnJvcnM7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRm9ySHR0cHModXJsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKCF1cmwpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgbGNVcmwgPSB1cmwudG9Mb3dlckNhc2UoKTtcblxuICAgICAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIChsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pIHx8XG4gICAgICAgICAgICAgICAgbGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSkgJiZcbiAgICAgICAgICAgIHRoaXMucmVxdWlyZUh0dHBzID09PSAncmVtb3RlT25seSdcbiAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBsY1VybC5zdGFydHNXaXRoKCdodHRwczovLycpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsOiBzdHJpbmcpIHtcbiAgICAgICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF1cmwpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB1cmwudG9Mb3dlckNhc2UoKS5zdGFydHNXaXRoKHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCkpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFJlZnJlc2hUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd0aW1lciBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdHRmb3JtJyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShfID0+IHtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xuICAgICAgICBjb25zdCBpZFRva2VuRXhwID0gdGhpcy5nZXRJZFRva2VuRXhwaXJhdGlvbigpIHx8IE51bWJlci5NQVhfVkFMVUU7XG4gICAgICAgIGNvbnN0IGFjY2Vzc1Rva2VuRXhwID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKSB8fCBOdW1iZXIuTUFYX1ZBTFVFO1xuICAgICAgICBjb25zdCB1c2VBY2Nlc3NUb2tlbkV4cCA9IGFjY2Vzc1Rva2VuRXhwIDw9IGlkVG9rZW5FeHA7XG5cbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpICYmIHVzZUFjY2Vzc1Rva2VuRXhwKSB7XG4gICAgICAgICAgICB0aGlzLnNldHVwQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkgJiYgIXVzZUFjY2Vzc1Rva2VuRXhwKSB7XG4gICAgICAgICAgICB0aGlzLnNldHVwSWRUb2tlblRpbWVyKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTtcbiAgICAgICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xuXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2FjY2Vzc190b2tlbicpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwSWRUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRJZFRva2VuRXhwaXJhdGlvbigpO1xuICAgICAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0SWRUb2tlblN0b3JlZEF0KCk7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcblxuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2lkX3Rva2VuJylcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcbiAgICAgICAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2xlYXJJZFRva2VuVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsY1RpbWVvdXQoc3RvcmVkQXQ6IG51bWJlciwgZXhwaXJhdGlvbjogbnVtYmVyKTogbnVtYmVyIHtcbiAgICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgZGVsdGEgPSAoZXhwaXJhdGlvbiAtIHN0b3JlZEF0KSAqIHRoaXMudGltZW91dEZhY3RvciAtIChub3cgLSBzdG9yZWRBdCk7XG4gICAgICAgIHJldHVybiBNYXRoLm1heCgwLCBkZWx0YSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogREVQUkVDQVRFRC4gVXNlIGEgcHJvdmlkZXIgZm9yIE9BdXRoU3RvcmFnZSBpbnN0ZWFkOlxuICAgICAqXG4gICAgICogeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IG9BdXRoU3RvcmFnZUZhY3RvcnkgfVxuICAgICAqIGV4cG9ydCBmdW5jdGlvbiBvQXV0aFN0b3JhZ2VGYWN0b3J5KCk6IE9BdXRoU3RvcmFnZSB7IHJldHVybiBsb2NhbFN0b3JhZ2U7IH1cbiAgICAgKiBTZXRzIGEgY3VzdG9tIHN0b3JhZ2UgdXNlZCB0byBzdG9yZSB0aGUgcmVjZWl2ZWRcbiAgICAgKiB0b2tlbnMgb24gY2xpZW50IHNpZGUuIEJ5IGRlZmF1bHQsIHRoZSBicm93c2VyJ3NcbiAgICAgKiBzZXNzaW9uU3RvcmFnZSBpcyB1c2VkLlxuICAgICAqIEBpZ25vcmVcbiAgICAgKlxuICAgICAqIEBwYXJhbSBzdG9yYWdlXG4gICAgICovXG4gICAgcHVibGljIHNldFN0b3JhZ2Uoc3RvcmFnZTogT0F1dGhTdG9yYWdlKTogdm9pZCB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UgPSBzdG9yYWdlO1xuICAgICAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMb2FkcyB0aGUgZGlzY292ZXJ5IGRvY3VtZW50IHRvIGNvbmZpZ3VyZSBtb3N0XG4gICAgICogcHJvcGVydGllcyBvZiB0aGlzIHNlcnZpY2UuIFRoZSB1cmwgb2YgdGhlIGRpc2NvdmVyeVxuICAgICAqIGRvY3VtZW50IGlzIGluZmVyZWQgZnJvbSB0aGUgaXNzdWVyJ3MgdXJsIGFjY29yZGluZ1xuICAgICAqIHRvIHRoZSBPcGVuSWQgQ29ubmVjdCBzcGVjLiBUbyB1c2UgYW5vdGhlciB1cmwgeW91XG4gICAgICogY2FuIHBhc3MgaXQgdG8gdG8gb3B0aW9uYWwgcGFyYW1ldGVyIGZ1bGxVcmwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gZnVsbFVybFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoZnVsbFVybDogc3RyaW5nID0gbnVsbCk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBpZiAoIWZ1bGxVcmwpIHtcbiAgICAgICAgICAgICAgICBmdWxsVXJsID0gdGhpcy5pc3N1ZXIgfHwgJyc7XG4gICAgICAgICAgICAgICAgaWYgKCFmdWxsVXJsLmVuZHNXaXRoKCcvJykpIHtcbiAgICAgICAgICAgICAgICAgICAgZnVsbFVybCArPSAnLyc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGZ1bGxVcmwgKz0gJy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uJztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHMoZnVsbFVybCkpIHtcbiAgICAgICAgICAgICAgICByZWplY3QoJ2lzc3VlciBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJyk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHAuZ2V0PE9pZGNEaXNjb3ZlcnlEb2M+KGZ1bGxVcmwpLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICBkb2MgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2MpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicsIG51bGwpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dpblVybCA9IGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50O1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ291dFVybCA9IGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCB8fCB0aGlzLmxvZ291dFVybDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ncmFudFR5cGVzU3VwcG9ydGVkID0gZG9jLmdyYW50X3R5cGVzX3N1cHBvcnRlZDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5pc3N1ZXIgPSBkb2MuaXNzdWVyO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnRva2VuRW5kcG9pbnQgPSBkb2MudG9rZW5fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMudXNlcmluZm9FbmRwb2ludCA9IGRvYy51c2VyaW5mb19lbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5qd2tzVXJpID0gZG9jLmp3a3NfdXJpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCA9IGRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSB8fCB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QubmV4dChkb2MpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvYWRKd2tzKClcbiAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuKGp3a3MgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogb2JqZWN0ID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNjb3ZlcnlEb2N1bWVudDogZG9jLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBqd2tzOiBqd2tzXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoZXZlbnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBsb2FkSndrcygpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2U8b2JqZWN0PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBpZiAodGhpcy5qd2tzVXJpKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5odHRwLmdldCh0aGlzLmp3a3NVcmkpLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgandrcyA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmp3a3MgPSBqd2tzO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJylcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGp3a3MpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgandrcycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdqd2tzX2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKG51bGwpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2M6IE9pZGNEaXNjb3ZlcnlEb2MpOiBib29sZWFuIHtcbiAgICAgICAgbGV0IGVycm9yczogc3RyaW5nW107XG5cbiAgICAgICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBkb2MuaXNzdWVyICE9PSB0aGlzLmlzc3Vlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2ludmFsaWQgaXNzdWVyIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgJ2V4cGVjdGVkOiAnICsgdGhpcy5pc3N1ZXIsXG4gICAgICAgICAgICAgICAgJ2N1cnJlbnQ6ICcgKyBkb2MuaXNzdWVyXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgYXV0aG9yaXphdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBlbmRfc2Vzc2lvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnRva2VuX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB0b2tlbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnVzZXJpbmZvX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB1c2VyaW5mb19lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmp3a3NfdXJpKTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgdmFsaWRhdGluZyBqd2tzX3VyaSBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnJvcnMpO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIWRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCBkaXNjb3ZlcnkgZG9jdW1lbnQnICtcbiAgICAgICAgICAgICAgICAnIGRvZXMgbm90IGNvbnRhaW4gYSBjaGVja19zZXNzaW9uX2lmcmFtZSBmaWVsZCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhblxuICAgICAqIGFjY2Vzc190b2tlbi4gQWZ0ZXIgcmVjZWl2aW5nIHRoZSBhY2Nlc3NfdG9rZW4sIHRoaXMgbWV0aG9kXG4gICAgICogdXNlcyBpdCB0byBxdWVyeSB0aGUgdXNlcmluZm8gZW5kcG9pbnQgaW4gb3JkZXIgdG8gZ2V0IGluZm9ybWF0aW9uXG4gICAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXG4gICAgICpcbiAgICAgKiBXaGVuIHVzaW5nIHRoaXMsIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cbiAgICAgKiBmYWlsLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAgICogQHBhcmFtIHBhc3N3b3JkXG4gICAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAgICovXG4gICAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvd0FuZExvYWRVc2VyUHJvZmlsZShcbiAgICAgICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICAgICAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgICAgICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyh1c2VyTmFtZSwgcGFzc3dvcmQsIGhlYWRlcnMpLnRoZW4oXG4gICAgICAgICAgICAoKSA9PiB0aGlzLmxvYWRVc2VyUHJvZmlsZSgpXG4gICAgICAgICk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTG9hZHMgdGhlIHVzZXIgcHJvZmlsZSBieSBhY2Nlc3NpbmcgdGhlIHVzZXIgaW5mbyBlbmRwb2ludCBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0LlxuICAgICAqXG4gICAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb24gZmFpbC5cbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIGlmICghdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignQ2FuIG5vdCBsb2FkIFVzZXIgUHJvZmlsZSB3aXRob3V0IGFjY2Vzc190b2tlbicpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMudXNlcmluZm9FbmRwb2ludCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAndXNlcmluZm9FbmRwb2ludCBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKClcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQ8VXNlckluZm8+KHRoaXMudXNlcmluZm9FbmRwb2ludCwgeyBoZWFkZXJzIH0pLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICBpbmZvID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygndXNlcmluZm8gcmVjZWl2ZWQnLCBpbmZvKTtcblxuICAgICAgICAgICAgICAgICAgICBjb25zdCBleGlzdGluZ0NsYWltcyA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub2lkYyAmJlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICghZXhpc3RpbmdDbGFpbXNbJ3N1YiddIHx8IGluZm8uc3ViICE9PSBleGlzdGluZ0NsYWltc1snc3ViJ10pXG4gICAgICAgICAgICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBlcnIgPVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnaWYgcHJvcGVydHkgb2lkYyBpcyB0cnVlLCB0aGUgcmVjZWl2ZWQgdXNlci1pZCAoc3ViKSBoYXMgdG8gYmUgdGhlIHVzZXItaWQgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdvZiB0aGUgdXNlciB0aGF0IGhhcyBsb2dnZWQgaW4gd2l0aCBvaWRjLlxcbicgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnaWYgeW91IGFyZSBub3QgdXNpbmcgb2lkYyBidXQganVzdCBvYXV0aDIgcGFzc3dvcmQgZmxvdyBzZXQgb2lkYyB0byBmYWxzZSc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpbmZvID0gT2JqZWN0LmFzc2lnbih7fSwgZXhpc3RpbmdDbGFpbXMsIGluZm8pO1xuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIEpTT04uc3RyaW5naWZ5KGluZm8pKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZGVkJykpO1xuICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGluZm8pO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW4gYWNjZXNzX3Rva2VuLlxuICAgICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgICAqIEBwYXJhbSBwYXNzd29yZFxuICAgICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgICAqL1xuICAgIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXG4gICAgICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnRva2VuRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBBIGBIdHRwUGFyYW1ldGVyQ29kZWNgIHRoYXQgdXNlcyBgZW5jb2RlVVJJQ29tcG9uZW50YCBhbmQgYGRlY29kZVVSSUNvbXBvbmVudGAgdG9cbiAgICAgICAgICAgICAqIHNlcmlhbGl6ZSBhbmQgcGFyc2UgVVJMIHBhcmFtZXRlciBrZXlzIGFuZCB2YWx1ZXMuXG4gICAgICAgICAgICAgKlxuICAgICAgICAgICAgICogQHN0YWJsZVxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoeyBlbmNvZGVyOiBuZXcgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMoKSB9KVxuICAgICAgICAgICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncGFzc3dvcmQnKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgICAgICAgICAuc2V0KCd1c2VybmFtZScsIHVzZXJOYW1lKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Bhc3N3b3JkJywgcGFzc3dvcmQpO1xuXG4gICAgICAgICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgICAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgICAgICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5odHRwXG4gICAgICAgICAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIHBhc3N3b3JkIGZsb3cnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCBlcnIpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXG4gICAgICogVGhpcyBkb2VzIG5vdCB3b3JrIGZvciBpbXBsaWNpdCBmbG93LCBiL2NcbiAgICAgKiB0aGVyZSBpcyBubyByZWZyZXNoX3Rva2VuIGluIHRoaXMgZmxvdy5cbiAgICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxuICAgICAqIG1ldGhvZCBzaWxlbnRSZWZyZXNoLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxvYmplY3Q+IHtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnRva2VuRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcbiAgICAgICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAgICAgICAgIC5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpXG4gICAgICAgICAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3JlZnJlc2hfdG9rZW4nLCB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSk7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5odHRwXG4gICAgICAgICAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAgICAgICAgIC5waXBlKHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmcm9tKHRoaXMucHJvY2Vzc0lkVG9rZW4odG9rZW5SZXNwb25zZS5pZF90b2tlbiwgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXAocmVzdWx0ID0+IHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCkpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXAoXyA9PiB0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gb2YodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgcGFzc3dvcmQgZmxvdycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XG4gICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xuICAgICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcbiAgICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgICAgICAgICBvbkxvZ2luRXJyb3I6IGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBvblRva2VuUmVjZWl2ZWQ6ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdzaWxlbnRseV9yZWZyZXNoZWQnKSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSkuY2F0Y2goZXJyID0+IHRoaXMuZGVidWcoJ3RyeUxvZ2luIGR1cmluZyBzaWxlbnQgcmVmcmVzaCBmYWlsZWQnLCBlcnIpKTtcbiAgICAgICAgfTtcblxuICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgICAgICdtZXNzYWdlJyxcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgICApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBlcmZvcm1zIGEgc2lsZW50IHJlZnJlc2ggZm9yIGltcGxpY2l0IGZsb3cuXG4gICAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGdldCBuZXcgdG9rZW5zIHdoZW4vYmVmb3JlXG4gICAgICogdGhlIGV4aXN0aW5nIHRva2VucyBleHBpcmUuXG4gICAgICovXG4gICAgcHVibGljIHNpbGVudFJlZnJlc2gocGFyYW1zOiBvYmplY3QgPSB7fSwgbm9Qcm9tcHQgPSB0cnVlKTogUHJvbWlzZTxPQXV0aEV2ZW50PiB7XG4gICAgICAgIGNvbnN0IGNsYWltczogb2JqZWN0ID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICBwYXJhbXNbJ2lkX3Rva2VuX2hpbnQnXSA9IHRoaXMuZ2V0SWRUb2tlbigpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAndG9rZW5FbmRwb2ludCBtdXN0IHVzZSBodHRwcywgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSByZXF1aXJlSHR0cHMgbXVzdCBhbGxvdyBodHRwJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0eXBlb2YgZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3NpbGVudCByZWZyZXNoIGlzIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0Zm9ybScpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcbiAgICAgICAgKTtcblxuICAgICAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcbiAgICAgICAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IGNsYWltc1snc3ViJ107XG5cbiAgICAgICAgY29uc3QgaWZyYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XG5cbiAgICAgICAgdGhpcy5zZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgY29uc3QgcmVkaXJlY3RVcmkgPSB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xuICAgICAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKG51bGwsIG51bGwsIHJlZGlyZWN0VXJpLCBub1Byb21wdCwgcGFyYW1zKS50aGVuKHVybCA9PiB7XG4gICAgICAgICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuXG4gICAgICAgICAgICBpZiAoIXRoaXMuc2lsZW50UmVmcmVzaFNob3dJRnJhbWUpIHtcbiAgICAgICAgICAgICAgICBpZnJhbWUuc3R5bGVbJ2Rpc3BsYXknXSA9ICdub25lJztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgY29uc3QgZXJyb3JzID0gdGhpcy5ldmVudHMucGlwZShcbiAgICAgICAgICAgIGZpbHRlcihlID0+IGUgaW5zdGFuY2VvZiBPQXV0aEVycm9yRXZlbnQpLFxuICAgICAgICAgICAgZmlyc3QoKVxuICAgICAgICApO1xuICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy5ldmVudHMucGlwZShcbiAgICAgICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpLFxuICAgICAgICAgICAgZmlyc3QoKVxuICAgICAgICApO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gb2YoXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JywgbnVsbClcbiAgICAgICAgKS5waXBlKGRlbGF5KHRoaXMuc2lsZW50UmVmcmVzaFRpbWVvdXQpKTtcblxuICAgICAgICByZXR1cm4gcmFjZShbZXJyb3JzLCBzdWNjZXNzLCB0aW1lb3V0XSlcbiAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgIHRhcChlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pLFxuICAgICAgICAgICAgICAgIG1hcChlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBPQXV0aEVycm9yRXZlbnQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93IGU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGU7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIC50b1Byb21pc2UoKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgaW5pdEltcGxpY2l0Rmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyLCB3aWR0aD86IG51bWJlciB9KSB7XG4gICAgICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICAgICAgICByZXR1cm4gdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSwgZmFsc2UsIHtcbiAgICAgICAgICAgIGRpc3BsYXk6ICdwb3B1cCdcbiAgICAgICAgfSkudGhlbih1cmwgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgICAgICBsZXQgd2luZG93UmVmID0gd2luZG93Lm9wZW4odXJsLCAnX2JsYW5rJywgdGhpcy5jYWxjdWxhdGVQb3B1cEZlYXR1cmVzKG9wdGlvbnMpKTtcblxuICAgICAgICAgICAgICAgIGNvbnN0IGNsZWFudXAgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93UmVmID0gbnVsbDtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgY29uc3QgbGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xuICAgICAgICAgICAgICAgICAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICAgICAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgICAgICAgIH0pLnRoZW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9LCBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zOiB7IGhlaWdodD86IG51bWJlciwgd2lkdGg/OiBudW1iZXIgfSkge1xuICAgICAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cbiAgICAgICAgY29uc3QgaGVpZ2h0ID0gb3B0aW9ucy5oZWlnaHQgfHwgNDcwO1xuICAgICAgICBjb25zdCB3aWR0aCA9IG9wdGlvbnMud2lkdGggfHwgNTAwO1xuICAgICAgICBjb25zdCBsZWZ0ID0gKHNjcmVlbi53aWR0aCAvIDIpIC0gKHdpZHRoIC8gMik7XG4gICAgICAgIGNvbnN0IHRvcCA9IChzY3JlZW4uaGVpZ2h0IC8gMikgLSAoaGVpZ2h0IC8gMik7XG4gICAgICAgIHJldHVybiBgbG9jYXRpb249bm8sdG9vbGJhcj1ubyx3aWR0aD0ke3dpZHRofSxoZWlnaHQ9JHtoZWlnaHR9LHRvcD0ke3RvcH0sbGVmdD0ke2xlZnR9YDtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KSB7XG4gICAgICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcblxuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xuICAgICAgICAgICAgZXhwZWN0ZWRQcmVmaXggKz0gdGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeDtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcblxuICAgICAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCkge1xuICAgICAgICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcbiAgICAgICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgY29uc3Qgb3JpZ2luID0gZS5vcmlnaW4udG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGNvbnN0IGlzc3VlciA9IHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCk7XG5cbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInKTtcblxuICAgICAgICAgICAgaWYgKCFpc3N1ZXIuc3RhcnRzV2l0aChvcmlnaW4pKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZyhcbiAgICAgICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInLFxuICAgICAgICAgICAgICAgICAgICAnd3Jvbmcgb3JpZ2luJyxcbiAgICAgICAgICAgICAgICAgICAgb3JpZ2luLFxuICAgICAgICAgICAgICAgICAgICAnZXhwZWN0ZWQnLFxuICAgICAgICAgICAgICAgICAgICBpc3N1ZXJcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBvbmx5IHJ1biBpbiBBbmd1bGFyIHpvbmUgaWYgaXQgaXMgJ2NoYW5nZWQnIG9yICdlcnJvcidcbiAgICAgICAgICAgIHN3aXRjaCAoZS5kYXRhKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAndW5jaGFuZ2VkJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ2NoYW5nZWQnOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdlcnJvcic6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25FcnJvcigpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ2dvdCBpbmZvIGZyb20gc2Vzc2lvbiBjaGVjayBpbmZyYW1lJywgZSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbiBjaGVjaycsICdzZXNzaW9uIHVuY2hhbmdlZCcpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xuICAgICAgICAvKiBldmVudHM6IHNlc3Npb25fY2hhbmdlZCwgcmVsb2dpbiwgc3RvcFRpbWVyLCBsb2dnZWRfb3V0Ki9cbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2NoYW5nZWQnKSk7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoKCkuY2F0Y2goXyA9PlxuICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGZhaWxlZCBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRoaXMud2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xuICAgICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgd2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKSB7XG4gICAgICAgIHRoaXMuZXZlbnRzXG4gICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICBmaWx0ZXIoXG4gICAgICAgICAgICAgICAgICAgIChlOiBPQXV0aEV2ZW50KSA9PlxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyB8fFxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcgfHxcbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xuICAgICAgICAgICAgICAgICksXG4gICAgICAgICAgICAgICAgZmlyc3QoKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICBpZiAoZS50eXBlICE9PSAnc2lsZW50bHlfcmVmcmVzaGVkJykge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkVycm9yKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fZXJyb3InKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpIHtcbiAgICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaW5pdFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICAgICAgaWYgKCF0aGlzLmNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuICAgICAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcbiAgICAgICAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgaWZyYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgICAgIGlmcmFtZS5pZCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZTtcblxuICAgICAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuICAgICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuICAgICAgICBpZnJhbWUuc3R5bGUuZGlzcGxheSA9ICdub25lJztcbiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuXG4gICAgICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdGFydFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXG4gICAgICAgICAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcbiAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcbiAgICAgICAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcik7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjaGVja1Nlc3Npb24oKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGlmcmFtZTogYW55ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcblxuICAgICAgICBpZiAoIWlmcmFtZSkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnY2hlY2tTZXNzaW9uIGRpZCBub3QgZmluZCBpZnJhbWUnLFxuICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG5cbiAgICAgICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5jbGllbnRJZCArICcgJyArIHNlc3Npb25TdGF0ZTtcbiAgICAgICAgaWZyYW1lLmNvbnRlbnRXaW5kb3cucG9zdE1lc3NhZ2UobWVzc2FnZSwgdGhpcy5pc3N1ZXIpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjcmVhdGVMb2dpblVybChcbiAgICAgICAgc3RhdGUgPSAnJyxcbiAgICAgICAgbG9naW5IaW50ID0gJycsXG4gICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpID0gJycsXG4gICAgICAgIG5vUHJvbXB0ID0gZmFsc2UsXG4gICAgICAgIHBhcmFtczogb2JqZWN0ID0ge31cbiAgICApIHtcbiAgICAgICAgY29uc3QgdGhhdCA9IHRoaXM7XG5cbiAgICAgICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XG5cbiAgICAgICAgaWYgKGN1c3RvbVJlZGlyZWN0VXJpKSB7XG4gICAgICAgICAgICByZWRpcmVjdFVyaSA9IGN1c3RvbVJlZGlyZWN0VXJpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmVkaXJlY3RVcmkgPSB0aGlzLnJlZGlyZWN0VXJpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgbm9uY2UgPSBhd2FpdCB0aGlzLmNyZWF0ZUFuZFNhdmVOb25jZSgpO1xuXG4gICAgICAgIGlmIChzdGF0ZSkge1xuICAgICAgICAgICAgc3RhdGUgPSBub25jZSArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IgKyBzdGF0ZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHN0YXRlID0gbm9uY2U7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGUpIHtcbiAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gdGhpcy5jb25maWcucmVzcG9uc2VUeXBlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaWYgKHRoaXMub2lkYyAmJiB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuIHRva2VuJztcbiAgICAgICAgICAgIH0gZWxzZSBpZiAodGhpcy5vaWRjICYmICF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAndG9rZW4nO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgc2VwZXJhdGlvbkNoYXIgPSB0aGF0LmxvZ2luVXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nO1xuXG4gICAgICAgIGxldCBzY29wZSA9IHRoYXQuc2NvcGU7XG5cbiAgICAgICAgaWYgKHRoaXMub2lkYyAmJiAhc2NvcGUubWF0Y2goLyhefFxccylvcGVuaWQoJHxcXHMpLykpIHtcbiAgICAgICAgICAgIHNjb3BlID0gJ29wZW5pZCAnICsgc2NvcGU7XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgdXJsID1cbiAgICAgICAgICAgIHRoYXQubG9naW5VcmwgK1xuICAgICAgICAgICAgc2VwZXJhdGlvbkNoYXIgK1xuICAgICAgICAgICAgJ3Jlc3BvbnNlX3R5cGU9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNwb25zZVR5cGUpICtcbiAgICAgICAgICAgICcmY2xpZW50X2lkPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQuY2xpZW50SWQpICtcbiAgICAgICAgICAgICcmc3RhdGU9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RhdGUpICtcbiAgICAgICAgICAgICcmcmVkaXJlY3RfdXJpPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArXG4gICAgICAgICAgICAnJnNjb3BlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHNjb3BlKTtcblxuICAgICAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJyAmJiAhdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgICAgICAgY29uc3QgW2NoYWxsZW5nZSwgdmVyaWZpZXJdID0gYXdhaXQgdGhpcy5jcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInLCB2ZXJpZmllcik7XG4gICAgICAgICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZT0nICsgY2hhbGxlbmdlO1xuICAgICAgICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYnO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGxvZ2luSGludCkge1xuICAgICAgICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhhdC5yZXNvdXJjZSkge1xuICAgICAgICAgICAgdXJsICs9ICcmcmVzb3VyY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc291cmNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGF0Lm9pZGMpIHtcbiAgICAgICAgICAgIHVybCArPSAnJm5vbmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQobm9uY2UpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vUHJvbXB0KSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XG4gICAgICAgIH1cblxuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhwYXJhbXMpKSB7XG4gICAgICAgICAgICB1cmwgKz1cbiAgICAgICAgICAgICAgICAnJicgKyBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudChwYXJhbXNba2V5XSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICB1cmwgKz1cbiAgICAgICAgICAgICAgICAgICAgJyYnICsga2V5ICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdXJsO1xuXG4gICAgfVxuXG4gICAgaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5pbkltcGxpY2l0Rmxvdykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IHRydWU7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnbG9naW5VcmwgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgYWRkUGFyYW1zOiBvYmplY3QgPSB7fTtcbiAgICAgICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcblxuICAgICAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIGxvZ2luSGludCA9IHBhcmFtcztcbiAgICAgICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xuICAgICAgICAgICAgYWRkUGFyYW1zID0gcGFyYW1zO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcbiAgICAgICAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRJbXBsaWNpdEZsb3cnLCBlcnJvcik7XG4gICAgICAgICAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3RhcnRzIHRoZSBpbXBsaWNpdCBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMnIGxvZ2luIHVybC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBhZGRpdGlvbmFsU3RhdGUgT3B0aW9uYWwgc3RhdGUgdGhhdCBpcyBwYXNzZWQgYXJvdW5kLlxuICAgICAqICBZb3UnbGwgZmluZCB0aGlzIHN0YXRlIGluIHRoZSBwcm9wZXJ0eSBgc3RhdGVgIGFmdGVyIGB0cnlMb2dpbmAgbG9nZ2VkIGluIHRoZSB1c2VyLlxuICAgICAqIEBwYXJhbSBwYXJhbXMgSGFzaCB3aXRoIGFkZGl0aW9uYWwgcGFyYW1ldGVyLiBJZiBpdCBpcyBhIHN0cmluZywgaXQgaXMgdXNlZCBmb3IgdGhlXG4gICAgICogICAgICAgICAgICAgICBwYXJhbWV0ZXIgbG9naW5IaW50IChmb3IgdGhlIHNha2Ugb2YgY29tcGF0aWJpbGl0eSB3aXRoIGZvcm1lciB2ZXJzaW9ucylcbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdEltcGxpY2l0RmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAgICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xuICAgICAqXG4gICAgICogQGRlc2NyaXB0aW9uIFRoaXMgbWV0aG9kIGFsbG93cyByZXNldHRpbmcgdGhlIGN1cnJlbnQgaW1wbGljdCBmbG93IGluIG9yZGVyIHRvIGJlIGluaXRpYWxpemVkIGFnYWluLlxuICAgICAqL1xuICAgIHB1YmxpYyByZXNldEltcGxpY2l0RmxvdygpOiB2b2lkIHtcbiAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgaWYgKG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKSB7XG4gICAgICAgICAgICBjb25zdCB0b2tlblBhcmFtcyA9IHtcbiAgICAgICAgICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxuICAgICAgICAgICAgICAgIGlkVG9rZW46IHRoYXQuZ2V0SWRUb2tlbigpLFxuICAgICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiB0aGF0LmdldEFjY2Vzc1Rva2VuKCksXG4gICAgICAgICAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCh0b2tlblBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICByZWZyZXNoVG9rZW46IHN0cmluZyxcbiAgICAgICAgZXhwaXJlc0luOiBudW1iZXIsXG4gICAgICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZ1xuICAgICk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcbiAgICAgICAgaWYgKGdyYW50ZWRTY29wZXMpIHtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzLnNwbGl0KCcrJykpKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICAgICAgICBpZiAoZXhwaXJlc0luKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzSW5NaWxsaVNlY29uZHMgPSBleHBpcmVzSW4gKiAxMDAwO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdy5nZXRUaW1lKCkgKyBleHBpcmVzSW5NaWxsaVNlY29uZHM7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2V4cGlyZXNfYXQnLCAnJyArIGV4cGlyZXNBdCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAocmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nLCByZWZyZXNoVG9rZW4pO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XG4gICAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3coKS50aGVuKF8gPT4gdHJ1ZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zKTtcbiAgICAgICAgfVxuICAgIH1cblxuXG4gICAgcHJpdmF0ZSBwYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgICAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgICAgcmV0dXJuIHt9O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICAgICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcblxuXG4gICAgfVxuXG4gICAgcHVibGljIHRyeUxvZ2luQ29kZUZsb3coKTogUHJvbWlzZTx2b2lkPiB7XG5cbiAgICAgICAgY29uc3QgcGFydHMgPSB0aGlzLnBhcnNlUXVlcnlTdHJpbmcod2luZG93LmxvY2F0aW9uLnNlYXJjaClcblxuICAgICAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBjb25zdCBocmVmID0gbG9jYXRpb24uaHJlZlxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XWNvZGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XXN0YXRlPVteJlxcJF0qLywgJycpXG4gICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2Vzc2lvbl9zdGF0ZT1bXiZcXCRdKi8sICcnKTtcblxuICAgICAgICBoaXN0b3J5LnJlcGxhY2VTdGF0ZShudWxsLCB3aW5kb3cubmFtZSwgaHJlZik7XG5cbiAgICAgICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgICAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2NvZGVfZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFub25jZUluU3RhdGUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcbiAgICAgICAgaWYgKCFzdWNjZXNzKSB7XG4gICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChldmVudCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY29kZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmdldFRva2VuRnJvbUNvZGUoY29kZSkudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdldCB0b2tlbiB1c2luZyBhbiBpbnRlcm1lZGlhdGUgY29kZS4gV29ya3MgZm9yIHRoZSBBdXRob3JpemF0aW9uIENvZGUgZmxvdy5cbiAgICAgKi9cbiAgICBwcml2YXRlIGdldFRva2VuRnJvbUNvZGUoY29kZTogc3RyaW5nKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcbiAgICAgICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAnYXV0aG9yaXphdGlvbl9jb2RlJylcbiAgICAgICAgICAgIC5zZXQoJ2NvZGUnLCBjb2RlKVxuICAgICAgICAgICAgLnNldCgncmVkaXJlY3RfdXJpJywgdGhpcy5yZWRpcmVjdFVyaSk7XG5cbiAgICAgICAgaWYgKCF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICAgICAgICBjb25zdCBwa2NpVmVyaWZpZXIgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcblxuICAgICAgICAgICAgaWYgKCFwa2NpVmVyaWZpZXIpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0kgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIHBrY2lWZXJpZmllcik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xuICAgIH1cblxuICAgIHByaXZhdGUgZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zOiBIdHRwUGFyYW1zKTogUHJvbWlzZTxvYmplY3Q+IHtcblxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC5zZXQoJ0NvbnRlbnQtVHlwZScsICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnKTtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnRva2VuRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgSHR0cC4gQWxzbyBjaGVjayBwcm9wZXJ0eSByZXF1aXJlSHR0cHMuJyk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAodG9rZW5SZXNwb25zZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9jZXNzSWRUb2tlbih0b2tlblJlc3BvbnNlLmlkX3Rva2VuLCB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbikuXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVhc29uKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChyZWFzb24pO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIChlcnIpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgZ2V0dGluZyB0b2tlbicsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpKTtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgYXJlIHRva2VucyBpbiB0aGUgaGFzaCBmcmFnbWVudFxuICAgICAqIGFzIGEgcmVzdWx0IG9mIHRoZSBpbXBsaWNpdCBmbG93LiBUaGVzZSB0b2tlbnMgYXJlXG4gICAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcbiAgICAgKiBjdXJyZW50IGNsaWVudC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAgICovXG4gICAgcHVibGljIHRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICAgICAgbGV0IHBhcnRzOiBvYmplY3Q7XG5cbiAgICAgICAgaWYgKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KSB7XG4gICAgICAgICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcyhvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5kZWJ1ZygncGFyc2VkIHVybCcsIHBhcnRzKTtcblxuICAgICAgICBjb25zdCBzdGF0ZSA9IHBhcnRzWydzdGF0ZSddO1xuXG4gICAgICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcbiAgICAgICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcblxuICAgICAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKG9wdGlvbnMsIHBhcnRzKTtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywge30sIHBhcnRzKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gcGFydHNbJ2FjY2Vzc190b2tlbiddO1xuICAgICAgICBjb25zdCBpZFRva2VuID0gcGFydHNbJ2lkX3Rva2VuJ107XG4gICAgICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XG4gICAgICAgIGNvbnN0IGdyYW50ZWRTY29wZXMgPSBwYXJ0c1snc2NvcGUnXTtcblxuICAgICAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcbiAgICAgICAgICAgICAgICAnRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIChvciBib3RoKSBtdXN0IGJlIHRydWUuJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjayAmJiAhc3RhdGUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLm9pZGMgJiYgIWlkVG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIXNlc3Npb25TdGF0ZSkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbiBjaGVja3MgKFNlc3Npb24gU3RhdHVzIENoYW5nZSBOb3RpZmljYXRpb24pICcgK1xuICAgICAgICAgICAgICAgICd3ZXJlIGFjdGl2YXRlZCBpbiB0aGUgY29uZmlndXJhdGlvbiBidXQgdGhlIGlkX3Rva2VuICcgK1xuICAgICAgICAgICAgICAgICdkb2VzIG5vdCBjb250YWluIGEgc2Vzc2lvbl9zdGF0ZSBjbGFpbSdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2spIHtcbiAgICAgICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcblxuICAgICAgICAgICAgaWYgKCFzdWNjZXNzKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChldmVudCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgIGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgICAgIG51bGwsXG4gICAgICAgICAgICAgICAgcGFydHNbJ2V4cGlyZXNfaW4nXSB8fCB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxuICAgICAgICAgICAgICAgIGdyYW50ZWRTY29wZXNcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMub2lkYykge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcblxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc0lkVG9rZW4oaWRUb2tlbiwgYWNjZXNzVG9rZW4pXG4gICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLnZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBvcHRpb25zXG4gICAgICAgICAgICAgICAgICAgICAgICAudmFsaWRhdGlvbkhhbmRsZXIoe1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZENsYWltczogcmVzdWx0LmlkVG9rZW5DbGFpbXMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbjogcmVzdWx0LmlkVG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdGU6IHN0YXRlXG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcbiAgICAgICAgICAgICAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XG4gICAgICAgICAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XG4gICAgICAgICAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHZhbGlkYXRpbmcgdG9rZW5zJyk7XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IocmVhc29uKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QocmVhc29uKTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByaXZhdGUgcGFyc2VTdGF0ZShzdGF0ZTogc3RyaW5nKTogW3N0cmluZywgc3RyaW5nXSB7XG4gICAgICAgIGxldCBub25jZSA9IHN0YXRlO1xuICAgICAgICBsZXQgdXNlclN0YXRlID0gJyc7XG5cbiAgICAgICAgaWYgKHN0YXRlKSB7XG4gICAgICAgICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xuICAgICAgICAgICAgaWYgKGlkeCA+IC0xKSB7XG4gICAgICAgICAgICAgICAgbm9uY2UgPSBzdGF0ZS5zdWJzdHIoMCwgaWR4KTtcbiAgICAgICAgICAgICAgICB1c2VyU3RhdGUgPSBzdGF0ZS5zdWJzdHIoaWR4ICsgdGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvci5sZW5ndGgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlTm9uY2UoXG4gICAgICAgIG5vbmNlSW5TdGF0ZTogc3RyaW5nXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICAgIGNvbnN0IHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcblxuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1ZhbGlkYXRpbmcgYWNjZXNzX3Rva2VuIGZhaWxlZCwgd3Jvbmcgc3RhdGUvbm9uY2UuJztcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyLCBzYXZlZE5vbmNlLCBub25jZUluU3RhdGUpO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdG9yZUlkVG9rZW4oaWRUb2tlbjogUGFyc2VkSWRUb2tlbikge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJywgaWRUb2tlbi5pZFRva2VuQ2xhaW1zSnNvbik7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcsICcnICsgaWRUb2tlbi5pZFRva2VuRXhwaXJlc0F0KTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGU6IHN0cmluZyk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnLCBzZXNzaW9uU3RhdGUpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRTZXNzaW9uU3RhdGUoKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVMb2dpbkVycm9yKG9wdGlvbnM6IExvZ2luT3B0aW9ucywgcGFydHM6IG9iamVjdCk6IHZvaWQge1xuICAgICAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcbiAgICAgICAgICAgIG9wdGlvbnMub25Mb2dpbkVycm9yKHBhcnRzKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIHByb2Nlc3NJZFRva2VuKFxuICAgICAgICBpZFRva2VuOiBzdHJpbmcsXG4gICAgICAgIGFjY2Vzc1Rva2VuOiBzdHJpbmcsXG4gICAgICAgIHNraXBOb25jZUNoZWNrID0gZmFsc2VcbiAgICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcbiAgICAgICAgY29uc3QgdG9rZW5QYXJ0cyA9IGlkVG9rZW4uc3BsaXQoJy4nKTtcbiAgICAgICAgY29uc3QgaGVhZGVyQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1swXSk7XG4gICAgICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XG4gICAgICAgIGNvbnN0IGhlYWRlciA9IEpTT04ucGFyc2UoaGVhZGVySnNvbik7XG4gICAgICAgIGNvbnN0IGNsYWltc0Jhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMV0pO1xuICAgICAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xuICAgICAgICBjb25zdCBjbGFpbXMgPSBKU09OLnBhcnNlKGNsYWltc0pzb24pO1xuICAgICAgICBjb25zdCBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuXG4gICAgICAgIGlmIChBcnJheS5pc0FycmF5KGNsYWltcy5hdWQpKSB7XG4gICAgICAgICAgICBpZiAoY2xhaW1zLmF1ZC5ldmVyeSh2ID0+IHYgIT09IHRoaXMuY2xpZW50SWQpKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgaWYgKGNsYWltcy5hdWQgIT09IHRoaXMuY2xpZW50SWQpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXVkaWVuY2U6ICcgKyBjbGFpbXMuYXVkO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghY2xhaW1zLnN1Yikge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ05vIHN1YiBjbGFpbSBpbiBpZF90b2tlbic7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcbiAgICAgICAgICogc2lsZW50UmVmcmVzaFN1YmplY3Qgd2hlbiBzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBvblxuICAgICAgICAgKiBXZSB3aWxsIHJlY29uc2lkZXIgaW4gYSBsYXRlciB2ZXJzaW9uIHRvIGRvIHRoaXNcbiAgICAgICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXG4gICAgICAgICAqL1xuICAgICAgICBpZiAoXG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICYmXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICE9PSBjbGFpbXNbJ3N1YiddXG4gICAgICAgICkge1xuICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAnQWZ0ZXIgcmVmcmVzaGluZywgd2UgZ290IGFuIGlkX3Rva2VuIGZvciBhbm90aGVyIHVzZXIgKHN1YikuICcgK1xuICAgICAgICAgICAgICAgIGBFeHBlY3RlZCBzdWI6ICR7dGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdH0sIHJlY2VpdmVkIHN1YjogJHtcbiAgICAgICAgICAgICAgICBjbGFpbXNbJ3N1YiddXG4gICAgICAgICAgICAgICAgfWA7XG5cbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFjbGFpbXMuaWF0KSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnTm8gaWF0IGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBjbGFpbXMuaXNzICE9PSB0aGlzLmlzc3Vlcikge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGlzc3VlcjogJyArIGNsYWltcy5pc3M7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghc2tpcE5vbmNlQ2hlY2sgJiYgY2xhaW1zLm5vbmNlICE9PSBzYXZlZE5vbmNlKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnV3Jvbmcgbm9uY2U6ICcgKyBjbGFpbXMubm9uY2U7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcbiAgICAgICAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcbiAgICAgICAgY29uc3QgZXhwaXJlc0F0TVNlYyA9IGNsYWltcy5leHAgKiAxMDAwO1xuICAgICAgICBjb25zdCBjbG9ja1NrZXdJbk1TZWMgPSAodGhpcy5jbG9ja1NrZXdJblNlYyB8fCA2MDApICogMTAwMDtcblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICBpc3N1ZWRBdE1TZWMgLSBjbG9ja1NrZXdJbk1TZWMgPj0gbm93IHx8XG4gICAgICAgICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdUb2tlbiBoYXMgZXhwaXJlZCc7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycik7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKHtcbiAgICAgICAgICAgICAgICBub3c6IG5vdyxcbiAgICAgICAgICAgICAgICBpc3N1ZWRBdE1TZWM6IGlzc3VlZEF0TVNlYyxcbiAgICAgICAgICAgICAgICBleHBpcmVzQXRNU2VjOiBleHBpcmVzQXRNU2VjXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcbiAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICAgICAgICBqd2tzOiB0aGlzLmp3a3MsXG4gICAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXG4gICAgICAgIH07XG5cblxuICAgICAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKVxuICAgICAgICAgIC50aGVuKGF0SGFzaFZhbGlkID0+IHtcbiAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXG4gICAgICAgICAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXG4gICAgICAgICAgICAgICFhdEhhc2hWYWxpZFxuICAgICAgICAgICkge1xuICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XG4gICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcbiAgICAgICAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xuICAgICAgICAgICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXG4gICAgICAgICAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXG4gICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgcmVjZWl2ZWQgY2xhaW1zIGFib3V0IHRoZSB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRJZGVudGl0eUNsYWltcygpOiBvYmplY3Qge1xuICAgICAgICBjb25zdCBjbGFpbXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcbiAgICAgICAgaWYgKCFjbGFpbXMpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBKU09OLnBhcnNlKGNsYWltcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZ3JhbnRlZCBzY29wZXMgZnJvbSB0aGUgc2VydmVyLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRHcmFudGVkU2NvcGVzKCk6IG9iamVjdCB7XG4gICAgICAgIGNvbnN0IHNjb3BlcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcbiAgICAgICAgaWYgKCFzY29wZXMpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBKU09OLnBhcnNlKHNjb3Blcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgY3VycmVudCBpZF90b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0SWRUb2tlbigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZVxuICAgICAgICAgICAgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuJylcbiAgICAgICAgICAgIDogbnVsbDtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcGFkQmFzZTY0KGJhc2U2NGRhdGEpOiBzdHJpbmcge1xuICAgICAgICB3aGlsZSAoYmFzZTY0ZGF0YS5sZW5ndGggJSA0ICE9PSAwKSB7XG4gICAgICAgICAgICBiYXNlNjRkYXRhICs9ICc9JztcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYmFzZTY0ZGF0YTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGFjY2Vzc190b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW4oKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2VcbiAgICAgICAgICAgID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW4nKVxuICAgICAgICAgICAgOiBudWxsO1xuICAgIH1cblxuICAgIHB1YmxpYyBnZXRSZWZyZXNoVG9rZW4oKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2VcbiAgICAgICAgICAgID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJylcbiAgICAgICAgICAgIDogbnVsbDtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGFjY2Vzc190b2tlblxuICAgICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSkge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGdldElkVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgaWRfdG9rZW5cbiAgICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSkge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDaGVja2VzLCB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgYWNjZXNzX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBoYXNWYWxpZEFjY2Vzc1Rva2VuKCk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAodGhpcy5nZXRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKTtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBpZF90b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaGFzVmFsaWRJZFRva2VuKCk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAodGhpcy5nZXRJZFRva2VuKCkpIHtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBhdXRoLWhlYWRlciB0aGF0IGNhbiBiZSB1c2VkXG4gICAgICogdG8gdHJhbnNtaXQgdGhlIGFjY2Vzc190b2tlbiB0byBhIHNlcnZpY2VcbiAgICAgKi9cbiAgICBwdWJsaWMgYXV0aG9yaXphdGlvbkhlYWRlcigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZXMgYWxsIHRva2VucyBhbmQgbG9ncyB0aGUgdXNlciBvdXQuXG4gICAgICogSWYgYSBsb2dvdXQgdXJsIGlzIGNvbmZpZ3VyZWQsIHRoZSB1c2VyIGlzXG4gICAgICogcmVkaXJlY3RlZCB0byBpdC5cbiAgICAgKiBAcGFyYW0gbm9SZWRpcmVjdFRvTG9nb3V0VXJsXG4gICAgICovXG4gICAgcHVibGljIGxvZ091dChub1JlZGlyZWN0VG9Mb2dvdXRVcmwgPSBmYWxzZSk6IHZvaWQge1xuICAgICAgICBjb25zdCBpZF90b2tlbiA9IHRoaXMuZ2V0SWRUb2tlbigpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgncmVmcmVzaF90b2tlbicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ25vbmNlJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZXhwaXJlc19hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBudWxsO1xuXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnbG9nb3V0JykpO1xuXG4gICAgICAgIGlmICghdGhpcy5sb2dvdXRVcmwpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBpZiAobm9SZWRpcmVjdFRvTG9nb3V0VXJsKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlkX3Rva2VuICYmICF0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGxvZ291dFVybDogc3RyaW5nO1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9nb3V0VXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICdsb2dvdXRVcmwgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBGb3IgYmFja3dhcmQgY29tcGF0aWJpbGl0eVxuICAgICAgICBpZiAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZigne3snKSA+IC0xKSB7XG4gICAgICAgICAgICBsb2dvdXRVcmwgPSB0aGlzLmxvZ291dFVybFxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cXHtcXHtpZF90b2tlblxcfVxcfS8sIGlkX3Rva2VuKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cXHtcXHtjbGllbnRfaWRcXH1cXH0vLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgfSBlbHNlIHtcblxuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKCk7XG5cbiAgICAgICAgICAgIGlmIChpZF90b2tlbikge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2lkX3Rva2VuX2hpbnQnLCBpZF90b2tlbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IHBvc3RMb2dvdXRVcmwgPSB0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xuICAgICAgICAgICAgaWYgKHBvc3RMb2dvdXRVcmwpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdwb3N0X2xvZ291dF9yZWRpcmVjdF91cmknLCBwb3N0TG9nb3V0VXJsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgbG9nb3V0VXJsID1cbiAgICAgICAgICAgICAgICB0aGlzLmxvZ291dFVybCArXG4gICAgICAgICAgICAgICAgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArXG4gICAgICAgICAgICAgICAgcGFyYW1zLnRvU3RyaW5nKCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5jb25maWcub3BlblVyaShsb2dvdXRVcmwpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQW5kU2F2ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuICAgICAgICByZXR1cm4gdGhpcy5jcmVhdGVOb25jZSgpLnRoZW4oZnVuY3Rpb24gKG5vbmNlOiBhbnkpIHtcbiAgICAgICAgICAgIHRoYXQuX3N0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XG4gICAgICAgICAgICByZXR1cm4gbm9uY2U7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgbmdPbkRlc3Ryb3koKSB7XG4gICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY3JlYXRlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7XG4gICAgICAgICAgICBpZiAodGhpcy5ybmdVcmwpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICdjcmVhdGVOb25jZSB3aXRoIHJuZy13ZWItYXBpIGhhcyBub3QgYmVlbiBpbXBsZW1lbnRlZCBzbyBmYXInXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLypcbiAgICAgICAgICAgICAqIFRoaXMgYWxwaGFiZXQgdXNlcyBhLXogQS1aIDAtOSBfLSBzeW1ib2xzLlxuICAgICAgICAgICAgICogU3ltYm9scyBvcmRlciB3YXMgY2hhbmdlZCBmb3IgYmV0dGVyIGd6aXAgY29tcHJlc3Npb24uXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGNvbnN0IHVybCA9ICdVaW50OEFyZG9tVmFsdWVzT2JqMDEyMzQ1Njc5QkNERUZHSElKS0xNTlBRUlNUV1hZWl9jZmdoa3Bxdnd4eXotJztcbiAgICAgICAgICAgIGxldCBzaXplID0gNDU7XG4gICAgICAgICAgICBsZXQgaWQgPSAnJztcblxuICAgICAgICAgICAgY29uc3QgY3J5cHRvID0gc2VsZi5jcnlwdG8gfHwgc2VsZlsnbXNDcnlwdG8nXTtcbiAgICAgICAgICAgIGlmIChjcnlwdG8pIHtcbiAgICAgICAgICAgICAgICBjb25zdCBieXRlcyA9IGNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoc2l6ZSkpO1xuICAgICAgICAgICAgICAgIHdoaWxlICgwIDwgc2l6ZS0tKSB7XG4gICAgICAgICAgICAgICAgICAgIGlkICs9IHVybFtieXRlc1tzaXplXSAmIDYzXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHdoaWxlICgwIDwgc2l6ZS0tKSB7XG4gICAgICAgICAgICAgICAgICAgIGlkICs9IHVybFtNYXRoLnJhbmRvbSgpICogNjQgfCAwXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJlc29sdmUoaWQpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgYXN5bmMgY2hlY2tBdEhhc2gocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBhdF9oYXNoLidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlQXRIYXNoKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNoZWNrU2lnbmF0dXJlKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PiB7XG4gICAgICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBzaWduYXR1cmUuJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUobnVsbCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMpO1xuICAgIH1cblxuXG4gICAgLyoqXG4gICAgICogU3RhcnQgdGhlIGltcGxpY2l0IGZsb3cgb3IgdGhlIGNvZGUgZmxvdyxcbiAgICAgKiBkZXBlbmRpbmcgb24geW91ciBjb25maWd1cmF0aW9uLlxuICAgICAqL1xuICAgIHB1YmxpYyBpbml0TG9naW5GbG93KFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zID0ge31cbiAgICApIHtcbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmluaXRDb2RlRmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5pbml0SW1wbGljaXRGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0cyB0aGUgYXV0aG9yaXphdGlvbiBjb2RlIGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXG4gICAgICogdGhlIGF1dGggc2VydmVycyBsb2dpbiB1cmwuXG4gICAgICovXG4gICAgcHVibGljIGluaXRDb2RlRmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgICAgICAgdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoXyA9PiB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcml2YXRlIGluaXRDb2RlRmxvd0ludGVybmFsKFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zID0ge31cbiAgICApOiB2b2lkIHtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdsb2dpblVybCBtdXN0IHVzZSBIdHRwLiBBbHNvIGNoZWNrIHByb3BlcnR5IHJlcXVpcmVIdHRwcy4nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCAnJywgbnVsbCwgZmFsc2UsIHBhcmFtcykudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKS5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0QXV0aG9yaXphdGlvbkNvZGVGbG93Jyk7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgfSk7XG5cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpOiBQcm9taXNlPFtzdHJpbmcsIHN0cmluZ10+IHtcblxuICAgICAgICBpZiAoIXRoaXMuY3J5cHRvKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1BLQ0kgc3VwcG9ydCBmb3IgY29kZSBmbG93IG5lZWRzIGEgQ3J5cHRvSGFuZGVyLiBEaWQgeW91IGltcG9ydCB0aGUgT0F1dGhNb2R1bGUgdXNpbmcgZm9yUm9vdCgpID8nKTtcbiAgICAgICAgfVxuXG5cbiAgICAgICAgY29uc3QgdmVyaWZpZXIgPSBhd2FpdCB0aGlzLmNyZWF0ZU5vbmNlKCk7XG4gICAgICAgIGNvbnN0IGNoYWxsZW5nZVJhdyA9IGF3YWl0IHRoaXMuY3J5cHRvLmNhbGNIYXNoKHZlcmlmaWVyLCAnc2hhLTI1NicpO1xuICAgICAgICBjb25zdCBjaGFsbGFuZ2UgPSBiYXNlNjRVcmxFbmNvZGUoY2hhbGxlbmdlUmF3KTtcblxuICAgICAgICByZXR1cm4gW2NoYWxsYW5nZSwgdmVyaWZpZXJdO1xuICAgIH1cbn1cbiJdfQ==