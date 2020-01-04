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
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch((/**
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFhLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxNQUFNLGdCQUFnQixDQUFDO0FBRTNFLE9BQU8sRUFDSCxpQkFBaUIsRUFFcEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBRUgsY0FBYyxFQUNkLGVBQWUsRUFDZixpQkFBaUIsRUFDcEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUNILFdBQVcsRUFDWCxZQUFZLEVBTWYsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3BELE9BQU8sRUFBRSxhQUFhLEVBQUUsTUFBTSxtQ0FBbUMsQ0FBQzs7Ozs7O0FBUWxFLE1BQU0sT0FBTyxZQUFhLFNBQVEsVUFBVTs7Ozs7Ozs7Ozs7SUErQ3hDLFlBQ2MsTUFBYyxFQUNkLElBQWdCLEVBQ2QsT0FBcUIs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TXRDLDZCQUFtQjs7Ozs7SUFFbkIscUNBQXlFOzs7OztJQUN6RSxzREFBa0Y7Ozs7O0lBQ2xGLDZEQUErRDs7Ozs7SUFDL0QsMkNBQWtEOzs7OztJQUNsRCxnQ0FBaUM7Ozs7O0lBQ2pDLHNEQUF1RDs7Ozs7SUFDdkQsa0RBQW1EOzs7OztJQUNuRCxpREFBbUQ7Ozs7O0lBQ25ELCtCQUEwQjs7Ozs7SUFDMUIseUNBQWlDOzs7OztJQUNqQyw0Q0FBdUM7Ozs7O0lBQ3ZDLHNDQUFpQzs7Ozs7SUFHN0IsOEJBQXdCOzs7OztJQUN4Qiw0QkFBMEI7Ozs7O0lBRzFCLDhCQUF3Qzs7Ozs7SUFDeEMsaUNBQXFDOzs7OztJQUNyQyw4QkFBNkI7Ozs7O0lBQzdCLDhCQUEyQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE5nWm9uZSwgT3B0aW9uYWwsIE9uRGVzdHJveSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMsIEh0dHBQYXJhbXMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBTdWJqZWN0LCBTdWJzY3JpcHRpb24sIG9mLCByYWNlLCBmcm9tIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBmaWx0ZXIsIGRlbGF5LCBmaXJzdCwgdGFwLCBtYXAsIHN3aXRjaE1hcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcblxuaW1wb3J0IHtcbiAgICBWYWxpZGF0aW9uSGFuZGxlcixcbiAgICBWYWxpZGF0aW9uUGFyYW1zXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcbmltcG9ydCB7XG4gICAgT0F1dGhFdmVudCxcbiAgICBPQXV0aEluZm9FdmVudCxcbiAgICBPQXV0aEVycm9yRXZlbnQsXG4gICAgT0F1dGhTdWNjZXNzRXZlbnRcbn0gZnJvbSAnLi9ldmVudHMnO1xuaW1wb3J0IHtcbiAgICBPQXV0aExvZ2dlcixcbiAgICBPQXV0aFN0b3JhZ2UsXG4gICAgTG9naW5PcHRpb25zLFxuICAgIFBhcnNlZElkVG9rZW4sXG4gICAgT2lkY0Rpc2NvdmVyeURvYyxcbiAgICBUb2tlblJlc3BvbnNlLFxuICAgIFVzZXJJbmZvXG59IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgYjY0RGVjb2RlVW5pY29kZSwgYmFzZTY0VXJsRW5jb2RlIH0gZnJvbSAnLi9iYXNlNjQtaGVscGVyJztcbmltcG9ydCB7IEF1dGhDb25maWcgfSBmcm9tICcuL2F1dGguY29uZmlnJztcbmltcG9ydCB7IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjIH0gZnJvbSAnLi9lbmNvZGVyJztcbmltcG9ydCB7IENyeXB0b0hhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vY3J5cHRvLWhhbmRsZXInO1xuXG4vKipcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcbiAqIE9JREMgYW5kIE9BdXRoMi4gU3VwcG9ydHMgaW1wbGljaXQgZmxvdyBhbmRcbiAqIHBhc3N3b3JkIGZsb3cuXG4gKi9cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBPQXV0aFNlcnZpY2UgZXh0ZW5kcyBBdXRoQ29uZmlnIGltcGxlbWVudHMgT25EZXN0cm95IHtcbiAgICAvLyBFeHRlbmRpbmcgQXV0aENvbmZpZyBpc3QganVzdCBmb3IgTEVHQUNZIHJlYXNvbnNcbiAgICAvLyB0byBub3QgYnJlYWsgZXhpc3RpbmcgY29kZS5cblxuICAgIC8qKlxuICAgICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXG4gICAgICogaWRfdG9rZW5zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSBmYWxzZTtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkOiBPYnNlcnZhYmxlPG9iamVjdD47XG5cbiAgICAvKipcbiAgICAgKiBJbmZvcm1zIGFib3V0IGV2ZW50cywgbGlrZSB0b2tlbl9yZWNlaXZlZCBvciB0b2tlbl9leHBpcmVzLlxuICAgICAqIFNlZSB0aGUgc3RyaW5nIGVudW0gRXZlbnRUeXBlIGZvciBhIGZ1bGwgbGlzdCBvZiBldmVudCB0eXBlcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZXZlbnRzOiBPYnNlcnZhYmxlPE9BdXRoRXZlbnQ+O1xuXG4gICAgLyoqXG4gICAgICogVGhlIHJlY2VpdmVkIChwYXNzZWQgYXJvdW5kKSBzdGF0ZSwgd2hlbiBsb2dnaW5nXG4gICAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxuICAgICAqL1xuICAgIHB1YmxpYyBzdGF0ZT8gPSAnJztcblxuICAgIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcbiAgICBwcm90ZWN0ZWQgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0OiBTdWJqZWN0PG9iamVjdD4gPSBuZXcgU3ViamVjdDxvYmplY3Q+KCk7XG4gICAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gICAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcbiAgICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIHNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gICAgcHJvdGVjdGVkIGp3a3NVcmk6IHN0cmluZztcbiAgICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrVGltZXI6IGFueTtcbiAgICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFN1YmplY3Q6IHN0cmluZztcbiAgICBwcm90ZWN0ZWQgaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcblxuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwcm90ZWN0ZWQgbmdab25lOiBOZ1pvbmUsXG4gICAgICAgIHByb3RlY3RlZCBodHRwOiBIdHRwQ2xpZW50LFxuICAgICAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXG4gICAgICAgIEBPcHRpb25hbCgpIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY29uZmlnOiBBdXRoQ29uZmlnLFxuICAgICAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxuICAgICAgICBwcm90ZWN0ZWQgbG9nZ2VyOiBPQXV0aExvZ2dlcixcbiAgICAgICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNyeXB0bzogQ3J5cHRvSGFuZGxlcixcbiAgICApIHtcbiAgICAgICAgc3VwZXIoKTtcblxuICAgICAgICB0aGlzLmRlYnVnKCdhbmd1bGFyLW9hdXRoMi1vaWRjIHY4LWJldGEnKTtcblxuICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuICAgICAgICB0aGlzLmV2ZW50cyA9IHRoaXMuZXZlbnRzU3ViamVjdC5hc09ic2VydmFibGUoKTtcblxuICAgICAgICBpZiAodG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyID0gdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChjb25maWcpIHtcbiAgICAgICAgICAgIHRoaXMuY29uZmlndXJlKGNvbmZpZyk7XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaWYgKHN0b3JhZ2UpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc3RvcmFnZSk7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc2Vzc2lvblN0b3JhZ2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlKSB7XG5cbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJ1xuICAgICAgICAgICAgICAgICsgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcbiAgICAgICAgICAgICAgICBlXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBjb25maWd1cmUgdGhlIHNlcnZpY2VcbiAgICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXG4gICAgICovXG4gICAgcHVibGljIGNvbmZpZ3VyZShjb25maWc6IEF1dGhDb25maWcpIHtcbiAgICAgICAgLy8gRm9yIHRoZSBzYWtlIG9mIGRvd253YXJkIGNvbXBhdGliaWxpdHkgd2l0aFxuICAgICAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxuICAgICAgICBPYmplY3QuYXNzaWduKHRoaXMsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gICAgfVxuXG4gICAgcHVibGljIHJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2soKSB7XG4gICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXG4gICAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXG4gICAgICogc2lsZW50IHJlZnJlc2hpbmcgd2lsbCBwYXVzZSBhbmQgbm90IHJlZnJlc2ggdGhlIHRva2VucyB1bnRpbCB0aGUgdXNlciBpc1xuICAgICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXG4gICAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXG4gICAgICogQHBhcmFtIGxpc3RlblRvIFNldHVwIGF1dG9tYXRpYyByZWZyZXNoIG9mIGEgc3BlY2lmaWMgdG9rZW4gdHlwZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2gocGFyYW1zOiBvYmplY3QgPSB7fSwgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55Jywgbm9Qcm9tcHQgPSB0cnVlKSB7XG4gICAgICBsZXQgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgICB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICB0YXAoKGUpID0+IHtcbiAgICAgICAgICBpZiAoZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSB7XG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcbiAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ2xvZ291dCcpIHtcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSBmYWxzZTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pLFxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9leHBpcmVzJylcbiAgICAgICkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XG4gICAgICAgIGlmICgobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmIHNob3VsZFJ1blNpbGVudFJlZnJlc2gpIHtcbiAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICB0aGlzLnJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpIHtcbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hUb2tlbigpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXG4gICAgICogZGlyZWN0bHkgY2hhaW5zIHVzaW5nIHRoZSBgdGhlbiguLi4pYCBwYXJ0IG9mIHRoZSBwcm9taXNlIHRvIGNhbGxcbiAgICAgKiB0aGUgYHRyeUxvZ2luKC4uLilgIG1ldGhvZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbiguLi4pYFxuICAgICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdEltcGxpY2l0RmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcbiAgICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kTG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihvcHRpb25zKS50aGVuKF8gPT4ge1xuICAgICAgICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8ICF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgICAgIHRoaXMuaW5pdEltcGxpY2l0RmxvdygpO1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBkZWJ1ZyguLi5hcmdzKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNob3dEZWJ1Z0luZm9ybWF0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5kZWJ1Zy5hcHBseShjb25zb2xlLCBhcmdzKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudCh1cmw6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgICAgICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuICAgICAgICBjb25zdCBodHRwc0NoZWNrID0gdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCk7XG4gICAgICAgIGNvbnN0IGlzc3VlckNoZWNrID0gdGhpcy52YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsKTtcblxuICAgICAgICBpZiAoIWh0dHBzQ2hlY2spIHtcbiAgICAgICAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAgICAgICAgICdodHRwcyBmb3IgYWxsIHVybHMgcmVxdWlyZWQuIEFsc28gZm9yIHVybHMgcmVjZWl2ZWQgYnkgZGlzY292ZXJ5LidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzc3VlckNoZWNrKSB7XG4gICAgICAgICAgICBlcnJvcnMucHVzaChcbiAgICAgICAgICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcbiAgICAgICAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZXJyb3JzO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWlyZUh0dHBzID09PSBmYWxzZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxuICAgICAgICAgICAgICAgIGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykpICYmXG4gICAgICAgICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXG4gICAgICAgICkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbGNVcmwuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybDogc3RyaW5nKSB7XG4gICAgICAgIGlmICghdGhpcy5zdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdXJsLnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aCh0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndGltZXIgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXR0Zm9ybScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwRXhwaXJhdGlvblRpbWVycygpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWRUb2tlbkV4cCA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKSB8fCBOdW1iZXIuTUFYX1ZBTFVFO1xuICAgICAgICBjb25zdCBhY2Nlc3NUb2tlbkV4cCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCkgfHwgTnVtYmVyLk1BWF9WQUxVRTtcbiAgICAgICAgY29uc3QgdXNlQWNjZXNzVG9rZW5FeHAgPSBhY2Nlc3NUb2tlbkV4cCA8PSBpZFRva2VuRXhwO1xuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSAmJiB1c2VBY2Nlc3NUb2tlbkV4cCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpICYmICF1c2VBY2Nlc3NUb2tlbkV4cCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk7XG4gICAgICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcblxuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdhY2Nlc3NfdG9rZW4nKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTtcbiAgICAgICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldElkVG9rZW5TdG9yZWRBdCgpO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFyQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFySWRUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGNUaW1lb3V0KHN0b3JlZEF0OiBudW1iZXIsIGV4cGlyYXRpb246IG51bWJlcik6IG51bWJlciB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IGRlbHRhID0gKGV4cGlyYXRpb24gLSBzdG9yZWRBdCkgKiB0aGlzLnRpbWVvdXRGYWN0b3IgLSAobm93IC0gc3RvcmVkQXQpO1xuICAgICAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcbiAgICAgKlxuICAgICAqIHsgcHJvdmlkZTogT0F1dGhTdG9yYWdlLCB1c2VGYWN0b3J5OiBvQXV0aFN0b3JhZ2VGYWN0b3J5IH1cbiAgICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XG4gICAgICogU2V0cyBhIGN1c3RvbSBzdG9yYWdlIHVzZWQgdG8gc3RvcmUgdGhlIHJlY2VpdmVkXG4gICAgICogdG9rZW5zIG9uIGNsaWVudCBzaWRlLiBCeSBkZWZhdWx0LCB0aGUgYnJvd3NlcidzXG4gICAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cbiAgICAgKiBAaWdub3JlXG4gICAgICpcbiAgICAgKiBAcGFyYW0gc3RvcmFnZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXRTdG9yYWdlKHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlID0gc3RvcmFnZTtcbiAgICAgICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxuICAgICAqIHByb3BlcnRpZXMgb2YgdGhpcyBzZXJ2aWNlLiBUaGUgdXJsIG9mIHRoZSBkaXNjb3ZlcnlcbiAgICAgKiBkb2N1bWVudCBpcyBpbmZlcmVkIGZyb20gdGhlIGlzc3VlcidzIHVybCBhY2NvcmRpbmdcbiAgICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxuICAgICAqIGNhbiBwYXNzIGl0IHRvIHRvIG9wdGlvbmFsIHBhcmFtZXRlciBmdWxsVXJsLlxuICAgICAqXG4gICAgICogQHBhcmFtIGZ1bGxVcmxcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50KGZ1bGxVcmw6IHN0cmluZyA9IG51bGwpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKCFmdWxsVXJsKSB7XG4gICAgICAgICAgICAgICAgZnVsbFVybCA9IHRoaXMuaXNzdWVyIHx8ICcnO1xuICAgICAgICAgICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XG4gICAgICAgICAgICAgICAgICAgIGZ1bGxVcmwgKz0gJy8nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBmdWxsVXJsICs9ICcud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbic7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKGZ1bGxVcmwpKSB7XG4gICAgICAgICAgICAgICAgcmVqZWN0KCdpc3N1ZXIgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCcpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5odHRwLmdldDxPaWRjRGlzY292ZXJ5RG9jPihmdWxsVXJsKS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgZG9jID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InLCBudWxsKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9naW5VcmwgPSBkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dvdXRVcmwgPSBkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQgfHwgdGhpcy5sb2dvdXRVcmw7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZ3JhbnRUeXBlc1N1cHBvcnRlZCA9IGRvYy5ncmFudF90eXBlc19zdXBwb3J0ZWQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuaXNzdWVyID0gZG9jLmlzc3VlcjtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy50b2tlbkVuZHBvaW50ID0gZG9jLnRva2VuX2VuZHBvaW50O1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnVzZXJpbmZvRW5kcG9pbnQgPSBkb2MudXNlcmluZm9fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuandrc1VyaSA9IGRvYy5qd2tzX3VyaTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPSBkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUgfHwgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0Lm5leHQoZG9jKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2FkSndrcygpXG4gICAgICAgICAgICAgICAgICAgICAgICAudGhlbihqd2tzID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzY292ZXJ5RG9jdW1lbnQ6IGRvYyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgandrczogandrc1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgbG9hZEp3a3MoKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xuICAgICAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQodGhpcy5qd2tzVXJpKS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIGp3a3MgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShqd2tzKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGp3a3MnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZShudWxsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XG4gICAgICAgIGxldCBlcnJvcnM6IHN0cmluZ1tdO1xuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdpbnZhbGlkIGlzc3VlciBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxuICAgICAgICAgICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGF1dGhvcml6YXRpb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy51c2VyaW5mb19lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdXNlcmluZm9fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JywgZXJyb3JzKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgZGlzY292ZXJ5IGRvY3VtZW50JyArXG4gICAgICAgICAgICAgICAgJyBkb2VzIG5vdCBjb250YWluIGEgY2hlY2tfc2Vzc2lvbl9pZnJhbWUgZmllbGQnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cbiAgICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgICAqIHVzZXMgaXQgdG8gcXVlcnkgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGluIG9yZGVyIHRvIGdldCBpbmZvcm1hdGlvblxuICAgICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxuICAgICAqXG4gICAgICogV2hlbiB1c2luZyB0aGlzLCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXG4gICAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXG4gICAgICogZmFpbC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgICAqIEBwYXJhbSBwYXNzd29yZFxuICAgICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgICAqL1xuICAgIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXG4gICAgICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3codXNlck5hbWUsIHBhc3N3b3JkLCBoZWFkZXJzKS50aGVuKFxuICAgICAgICAgICAgKCkgPT4gdGhpcy5sb2FkVXNlclByb2ZpbGUoKVxuICAgICAgICApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExvYWRzIHRoZSB1c2VyIHByb2ZpbGUgYnkgYWNjZXNzaW5nIHRoZSB1c2VyIGluZm8gZW5kcG9pbnQgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICAgKlxuICAgICAqIFdoZW4gdXNpbmcgdGhpcyB3aXRoIE9BdXRoMiBwYXNzd29yZCBmbG93LCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXG4gICAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uIGZhaWwuXG4gICAgICovXG4gICAgcHVibGljIGxvYWRVc2VyUHJvZmlsZSgpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3VzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHAuZ2V0PFVzZXJJbmZvPih0aGlzLnVzZXJpbmZvRW5kcG9pbnQsIHsgaGVhZGVycyB9KS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgaW5mbyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XG5cbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLnNraXBTdWJqZWN0Q2hlY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGMgJiZcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoIWV4aXN0aW5nQ2xhaW1zWydzdWInXSB8fCBpbmZvLnN1YiAhPT0gZXhpc3RpbmdDbGFpbXNbJ3N1YiddKVxuICAgICAgICAgICAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHByb3BlcnR5IG9pZGMgaXMgdHJ1ZSwgdGhlIHJlY2VpdmVkIHVzZXItaWQgKHN1YikgaGFzIHRvIGJlIHRoZSB1c2VyLWlkICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb2YgdGhlIHVzZXIgdGhhdCBoYXMgbG9nZ2VkIGluIHdpdGggb2lkYy5cXG4nICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaW5mbyA9IE9iamVjdC5hc3NpZ24oe30sIGV4aXN0aW5nQ2xhaW1zLCBpbmZvKTtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShpbmZvKTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIHVzZXIgaW5mbycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cbiAgICAgKiBAcGFyYW0gdXNlck5hbWVcbiAgICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxuICAgICAgICB1c2VyTmFtZTogc3RyaW5nLFxuICAgICAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICAgKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogQSBgSHR0cFBhcmFtZXRlckNvZGVjYCB0aGF0IHVzZXMgYGVuY29kZVVSSUNvbXBvbmVudGAgYW5kIGBkZWNvZGVVUklDb21wb25lbnRgIHRvXG4gICAgICAgICAgICAgKiBzZXJpYWxpemUgYW5kIHBhcnNlIFVSTCBwYXJhbWV0ZXIga2V5cyBhbmQgdmFsdWVzLlxuICAgICAgICAgICAgICpcbiAgICAgICAgICAgICAqIEBzdGFibGVcbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcbiAgICAgICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3Bhc3N3b3JkJylcbiAgICAgICAgICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgICAgICAgICAgLnNldCgndXNlcm5hbWUnLCB1c2VyTmFtZSlcbiAgICAgICAgICAgICAgICAuc2V0KCdwYXNzd29yZCcsIHBhc3N3b3JkKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICAgICAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cFxuICAgICAgICAgICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgdG9rZW4gdXNpbmcgYSByZWZyZXNoX3Rva2VuLlxuICAgICAqIFRoaXMgZG9lcyBub3Qgd29yayBmb3IgaW1wbGljaXQgZmxvdywgYi9jXG4gICAgICogdGhlcmUgaXMgbm8gcmVmcmVzaF90b2tlbiBpbiB0aGlzIGZsb3cuXG4gICAgICogQSBzb2x1dGlvbiBmb3IgdGhpcyBpcyBwcm92aWRlZCBieSB0aGVcbiAgICAgKiBtZXRob2Qgc2lsZW50UmVmcmVzaC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVmcmVzaFRva2VuKCk6IFByb21pc2U8b2JqZWN0PiB7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy50b2tlbkVuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICd0b2tlbkVuZHBvaW50IG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcbiAgICAgICAgICAgICAgICAuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgICAgICAgICAuc2V0KCdyZWZyZXNoX3Rva2VuJywgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykpO1xuXG4gICAgICAgICAgICBpZiAodGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cFxuICAgICAgICAgICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcbiAgICAgICAgICAgICAgICAucGlwZShzd2l0Y2hNYXAodG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZnJvbSh0aGlzLnByb2Nlc3NJZFRva2VuKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLCB0cnVlKSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFwKF8gPT4gdG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9mKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIHBhc3N3b3JkIGZsb3cnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgICAgb25Mb2dpbkVycm9yOiBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgb25Ub2tlblJlY2VpdmVkOiAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBnZXQgbmV3IHRva2VucyB3aGVuL2JlZm9yZVxuICAgICAqIHRoZSBleGlzdGluZyB0b2tlbnMgZXhwaXJlLlxuICAgICAqL1xuICAgIHB1YmxpYyBzaWxlbnRSZWZyZXNoKHBhcmFtczogb2JqZWN0ID0ge30sIG5vUHJvbXB0ID0gdHJ1ZSk6IFByb21pc2U8T0F1dGhFdmVudD4ge1xuICAgICAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgICAgICBpZiAodGhpcy51c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2ggJiYgdGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgcGFyYW1zWydpZF90b2tlbl9oaW50J10gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXG4gICAgICAgICk7XG5cbiAgICAgICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBjbGFpbXNbJ3N1YiddO1xuXG4gICAgICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgICAgICBpZnJhbWUuaWQgPSB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lO1xuXG4gICAgICAgIHRoaXMuc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xuICAgICAgICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcblxuICAgICAgICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XG4gICAgICAgICAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGNvbnN0IGVycm9ycyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IG9mKFxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXG4gICAgICAgICkucGlwZShkZWxheSh0aGlzLnNpbGVudFJlZnJlc2hUaW1lb3V0KSk7XG5cbiAgICAgICAgcmV0dXJuIHJhY2UoW2Vycm9ycywgc3VjY2VzcywgdGltZW91dF0pXG4gICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICB0YXAoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0Jykge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KSxcbiAgICAgICAgICAgICAgICBtYXAoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBlO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAudG9Qcm9taXNlKCk7XG4gICAgfVxuXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3dJblBvcHVwKG9wdGlvbnM/OiB7IGhlaWdodD86IG51bWJlciwgd2lkdGg/OiBudW1iZXIgfSkge1xuICAgICAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcbiAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlTG9naW5VcmwobnVsbCwgbnVsbCwgdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmksIGZhbHNlLCB7XG4gICAgICAgICAgICBkaXNwbGF5OiAncG9wdXAnXG4gICAgICAgIH0pLnRoZW4odXJsID0+IHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKHVybCwgJ19ibGFuaycsIHRoaXMuY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zKSk7XG5cbiAgICAgICAgICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93UmVmLmNsb3NlKCk7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIGNvbnN0IGxpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcbiAgICAgICAgICAgICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICAgICAgICAgICAgICB9KS50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICAgICAgICAgICAgfSwgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczogeyBoZWlnaHQ/OiBudW1iZXIsIHdpZHRoPzogbnVtYmVyIH0pIHtcbiAgICAgICAgLy8gU3BlY2lmeSBhbiBzdGF0aWMgaGVpZ2h0IGFuZCB3aWR0aCBhbmQgY2FsY3VsYXRlIGNlbnRlcmVkIHBvc2l0aW9uXG4gICAgICAgIGNvbnN0IGhlaWdodCA9IG9wdGlvbnMuaGVpZ2h0IHx8IDQ3MDtcbiAgICAgICAgY29uc3Qgd2lkdGggPSBvcHRpb25zLndpZHRoIHx8IDUwMDtcbiAgICAgICAgY29uc3QgbGVmdCA9IChzY3JlZW4ud2lkdGggLyAyKSAtICh3aWR0aCAvIDIpO1xuICAgICAgICBjb25zdCB0b3AgPSAoc2NyZWVuLmhlaWdodCAvIDIpIC0gKGhlaWdodCAvIDIpO1xuICAgICAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGU6IE1lc3NhZ2VFdmVudCkge1xuICAgICAgICBsZXQgZXhwZWN0ZWRQcmVmaXggPSAnIyc7XG5cbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXgpIHtcbiAgICAgICAgICAgIGV4cGVjdGVkUHJlZml4ICs9IHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWUgfHwgIWUuZGF0YSB8fCB0eXBlb2YgZS5kYXRhICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgcHJlZml4ZWRNZXNzYWdlOiBzdHJpbmcgPSBlLmRhdGE7XG5cbiAgICAgICAgaWYgKCFwcmVmaXhlZE1lc3NhZ2Uuc3RhcnRzV2l0aChleHBlY3RlZFByZWZpeCkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiAnIycgKyBwcmVmaXhlZE1lc3NhZ2Uuc3Vic3RyKGV4cGVjdGVkUHJlZml4Lmxlbmd0aCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uQ2hlY2tJRnJhbWVVcmwnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG4gICAgICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbl9zdGF0ZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIHRoaXMucmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG9yaWdpbiA9IGUub3JpZ2luLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICBjb25zdCBpc3N1ZXIgPSB0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpO1xuXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyk7XG5cbiAgICAgICAgICAgIGlmICghaXNzdWVyLnN0YXJ0c1dpdGgob3JpZ2luKSkge1xuICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoXG4gICAgICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyxcbiAgICAgICAgICAgICAgICAgICAgJ3dyb25nIG9yaWdpbicsXG4gICAgICAgICAgICAgICAgICAgIG9yaWdpbixcbiAgICAgICAgICAgICAgICAgICAgJ2V4cGVjdGVkJyxcbiAgICAgICAgICAgICAgICAgICAgaXNzdWVyXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gb25seSBydW4gaW4gQW5ndWxhciB6b25lIGlmIGl0IGlzICdjaGFuZ2VkJyBvciAnZXJyb3InXG4gICAgICAgICAgICBzd2l0Y2ggKGUuZGF0YSkge1xuICAgICAgICAgICAgICAgIGNhc2UgJ3VuY2hhbmdlZCc6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdjaGFuZ2VkJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkNoYW5nZSgpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnZXJyb3InOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uRXJyb3IoKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdnb3QgaW5mbyBmcm9tIHNlc3Npb24gY2hlY2sgaW5mcmFtZScsIGUpO1xuICAgICAgICB9O1xuXG4gICAgICAgIC8vIHByZXZlbnQgQW5ndWxhciBmcm9tIHJlZnJlc2hpbmcgdGhlIHZpZXcgb24gZXZlcnkgbWVzc2FnZSAocnVucyBpbiBpbnRlcnZhbHMpXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuZGVidWcoJ3Nlc3Npb24gY2hlY2snLCAnc2Vzc2lvbiB1bmNoYW5nZWQnKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICAgICAgLyogZXZlbnRzOiBzZXNzaW9uX2NoYW5nZWQsIHJlbG9naW4sIHN0b3BUaW1lciwgbG9nZ2VkX291dCovXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9jaGFuZ2VkJykpO1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaCgpLmNhdGNoKF8gPT5cbiAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBmYWlsZWQgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJylcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICB0aGlzLndhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHdhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCkge1xuICAgICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAgICAgLnBpcGUoXG4gICAgICAgICAgICAgICAgZmlsdGVyKFxuICAgICAgICAgICAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcgfHxcbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnIHx8XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcbiAgICAgICAgICAgICAgICApLFxuICAgICAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKGUudHlwZSAhPT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25FcnJvcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2Vycm9yJykpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKSB7XG4gICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGluaXRTZXNzaW9uQ2hlY2soKTogdm9pZCB7XG4gICAgICAgIGlmICghdGhpcy5jYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcbiAgICAgICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgICAgICBpZnJhbWUuaWQgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWU7XG5cbiAgICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICBjb25zdCB1cmwgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcbiAgICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcbiAgICAgICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XG4gICAgICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcblxuICAgICAgICB0aGlzLnN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IHNldEludGVydmFsKFxuICAgICAgICAgICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uLmJpbmQodGhpcyksXG4gICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJbnRlcnZhbGxcbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja1RpbWVyKSB7XG4gICAgICAgICAgICBjbGVhckludGVydmFsKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpO1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xuICAgICAgICBjb25zdCBpZnJhbWU6IGFueSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZSk7XG5cbiAgICAgICAgaWYgKCFpZnJhbWUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcbiAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuXG4gICAgICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XG4gICAgICAgIGlmcmFtZS5jb250ZW50V2luZG93LnBvc3RNZXNzYWdlKG1lc3NhZ2UsIHRoaXMuaXNzdWVyKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXG4gICAgICAgIHN0YXRlID0gJycsXG4gICAgICAgIGxvZ2luSGludCA9ICcnLFxuICAgICAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxuICAgICAgICBub1Byb21wdCA9IGZhbHNlLFxuICAgICAgICBwYXJhbXM6IG9iamVjdCA9IHt9XG4gICAgKSB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuXG4gICAgICAgIGxldCByZWRpcmVjdFVyaTogc3RyaW5nO1xuXG4gICAgICAgIGlmIChjdXN0b21SZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgcmVkaXJlY3RVcmkgPSBjdXN0b21SZWRpcmVjdFVyaTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG5vbmNlID0gYXdhaXQgdGhpcy5jcmVhdGVBbmRTYXZlTm9uY2UoKTtcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICAgIHN0YXRlID0gbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgc3RhdGU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzdGF0ZSA9IG5vbmNlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyBvciBib3RoIG11c3QgYmUgdHJ1ZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlKSB7XG4gICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHRoaXMub2lkYyAmJiAhdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbic7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHNlcGVyYXRpb25DaGFyID0gdGhhdC5sb2dpblVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JztcblxuICAgICAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xuXG4gICAgICAgIGlmICh0aGlzLm9pZGMgJiYgIXNjb3BlLm1hdGNoKC8oXnxcXHMpb3BlbmlkKCR8XFxzKS8pKSB7XG4gICAgICAgICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IHVybCA9XG4gICAgICAgICAgICB0aGF0LmxvZ2luVXJsICtcbiAgICAgICAgICAgIHNlcGVyYXRpb25DaGFyICtcbiAgICAgICAgICAgICdyZXNwb25zZV90eXBlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXG4gICAgICAgICAgICAnJmNsaWVudF9pZD0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXG4gICAgICAgICAgICAnJnN0YXRlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKSArXG4gICAgICAgICAgICAnJnJlZGlyZWN0X3VyaT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xuICAgICAgICAgICAgJyZzY29wZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgJiYgIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgICAgICAgIGNvbnN0IFtjaGFsbGVuZ2UsIHZlcmlmaWVyXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xuICAgICAgICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcbiAgICAgICAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JztcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChsb2dpbkhpbnQpIHtcbiAgICAgICAgICAgIHVybCArPSAnJmxvZ2luX2hpbnQ9JyArIGVuY29kZVVSSUNvbXBvbmVudChsb2dpbkhpbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcbiAgICAgICAgICAgIHVybCArPSAnJnJlc291cmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNvdXJjZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhhdC5vaWRjKSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZub25jZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG5vbmNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub1Byb21wdCkge1xuICAgICAgICAgICAgdXJsICs9ICcmcHJvbXB0PW5vbmUnO1xuICAgICAgICB9XG5cbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xuICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgJyYnICsgZW5jb2RlVVJJQ29tcG9uZW50KGtleSkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQocGFyYW1zW2tleV0pO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHVybDtcbiAgICAgICAgXG4gICAgfVxuXG4gICAgaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5pbkltcGxpY2l0Rmxvdykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IHRydWU7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnbG9naW5VcmwgbXVzdCB1c2UgaHR0cHMsIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgcmVxdWlyZUh0dHBzIG11c3QgYWxsb3cgaHR0cCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgYWRkUGFyYW1zOiBvYmplY3QgPSB7fTtcbiAgICAgICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcblxuICAgICAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIGxvZ2luSGludCA9IHBhcmFtcztcbiAgICAgICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xuICAgICAgICAgICAgYWRkUGFyYW1zID0gcGFyYW1zO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcbiAgICAgICAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRJbXBsaWNpdEZsb3cnLCBlcnJvcik7XG4gICAgICAgICAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3RhcnRzIHRoZSBpbXBsaWNpdCBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMnIGxvZ2luIHVybC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBhZGRpdGlvbmFsU3RhdGUgT3B0aW9uYWwgc3RhdGUgdGhhdCBpcyBwYXNzZWQgYXJvdW5kLlxuICAgICAqICBZb3UnbGwgZmluZCB0aGlzIHN0YXRlIGluIHRoZSBwcm9wZXJ0eSBgc3RhdGVgIGFmdGVyIGB0cnlMb2dpbmAgbG9nZ2VkIGluIHRoZSB1c2VyLlxuICAgICAqIEBwYXJhbSBwYXJhbXMgSGFzaCB3aXRoIGFkZGl0aW9uYWwgcGFyYW1ldGVyLiBJZiBpdCBpcyBhIHN0cmluZywgaXQgaXMgdXNlZCBmb3IgdGhlXG4gICAgICogICAgICAgICAgICAgICBwYXJhbWV0ZXIgbG9naW5IaW50IChmb3IgdGhlIHNha2Ugb2YgY29tcGF0aWJpbGl0eSB3aXRoIGZvcm1lciB2ZXJzaW9ucylcbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdEltcGxpY2l0RmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAgICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xuICAgICAqXG4gICAgICogQGRlc2NyaXB0aW9uIFRoaXMgbWV0aG9kIGFsbG93cyByZXNldHRpbmcgdGhlIGN1cnJlbnQgaW1wbGljdCBmbG93IGluIG9yZGVyIHRvIGJlIGluaXRpYWxpemVkIGFnYWluLlxuICAgICAqL1xuICAgIHB1YmxpYyByZXNldEltcGxpY2l0RmxvdygpOiB2b2lkIHtcbiAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgaWYgKG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKSB7XG4gICAgICAgICAgICBjb25zdCB0b2tlblBhcmFtcyA9IHtcbiAgICAgICAgICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxuICAgICAgICAgICAgICAgIGlkVG9rZW46IHRoYXQuZ2V0SWRUb2tlbigpLFxuICAgICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiB0aGF0LmdldEFjY2Vzc1Rva2VuKCksXG4gICAgICAgICAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCh0b2tlblBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICByZWZyZXNoVG9rZW46IHN0cmluZyxcbiAgICAgICAgZXhwaXJlc0luOiBudW1iZXIsXG4gICAgICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZ1xuICAgICk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcbiAgICAgICAgaWYgKGdyYW50ZWRTY29wZXMpIHtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzLnNwbGl0KCcrJykpKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICAgICAgICBpZiAoZXhwaXJlc0luKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzSW5NaWxsaVNlY29uZHMgPSBleHBpcmVzSW4gKiAxMDAwO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdy5nZXRUaW1lKCkgKyBleHBpcmVzSW5NaWxsaVNlY29uZHM7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2V4cGlyZXNfYXQnLCAnJyArIGV4cGlyZXNBdCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAocmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nLCByZWZyZXNoVG9rZW4pO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XG4gICAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3coKS50aGVuKF8gPT4gdHJ1ZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zKTtcbiAgICAgICAgfVxuICAgIH1cblxuXG4gICAgcHJpdmF0ZSBwYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgICAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgICAgcmV0dXJuIHt9O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICAgICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcblxuXG4gICAgfVxuXG4gICAgcHVibGljIHRyeUxvZ2luQ29kZUZsb3coKTogUHJvbWlzZTx2b2lkPiB7XG5cbiAgICAgICAgY29uc3QgcGFydHMgPSB0aGlzLnBhcnNlUXVlcnlTdHJpbmcod2luZG93LmxvY2F0aW9uLnNlYXJjaClcblxuICAgICAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBjb25zdCBocmVmID0gbG9jYXRpb24uaHJlZlxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XWNvZGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XXN0YXRlPVteJlxcJF0qLywgJycpXG4gICAgICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2Vzc2lvbl9zdGF0ZT1bXiZcXCRdKi8sICcnKTtcblxuICAgICAgICBoaXN0b3J5LnJlcGxhY2VTdGF0ZShudWxsLCB3aW5kb3cubmFtZSwgaHJlZik7XG5cbiAgICAgICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgICAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2NvZGVfZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFub25jZUluU3RhdGUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcbiAgICAgICAgaWYgKCFzdWNjZXNzKSB7XG4gICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChldmVudCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY29kZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmdldFRva2VuRnJvbUNvZGUoY29kZSkudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdldCB0b2tlbiB1c2luZyBhbiBpbnRlcm1lZGlhdGUgY29kZS4gV29ya3MgZm9yIHRoZSBBdXRob3JpemF0aW9uIENvZGUgZmxvdy5cbiAgICAgKi9cbiAgICBwcml2YXRlIGdldFRva2VuRnJvbUNvZGUoY29kZTogc3RyaW5nKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcbiAgICAgICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAnYXV0aG9yaXphdGlvbl9jb2RlJylcbiAgICAgICAgICAgIC5zZXQoJ2NvZGUnLCBjb2RlKVxuICAgICAgICAgICAgLnNldCgncmVkaXJlY3RfdXJpJywgdGhpcy5yZWRpcmVjdFVyaSk7XG5cbiAgICAgICAgaWYgKCF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICAgICAgICBjb25zdCBwa2NpVmVyaWZpZXIgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcblxuICAgICAgICAgICAgaWYgKCFwa2NpVmVyaWZpZXIpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0kgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIHBrY2lWZXJpZmllcik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xuICAgIH1cblxuICAgIHByaXZhdGUgZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zOiBIdHRwUGFyYW1zKTogUHJvbWlzZTxvYmplY3Q+IHtcblxuICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC5zZXQoJ0NvbnRlbnQtVHlwZScsICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnKTtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnRva2VuRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3Rva2VuRW5kcG9pbnQgbXVzdCB1c2UgSHR0cC4gQWxzbyBjaGVjayBwcm9wZXJ0eSByZXF1aXJlSHR0cHMuJyk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAodG9rZW5SZXNwb25zZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbiwgXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sIFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMub2lkYyAmJiB0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuKS4gIFxuICAgICAgICAgICAgICAgICAgICAgICAgdGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2F0Y2gocmVhc29uID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKHJlYXNvbik7XG4gICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuICAgICAgICAgICAgXG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAoZXJyKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGFyZSB0b2tlbnMgaW4gdGhlIGhhc2ggZnJhZ21lbnRcbiAgICAgKiBhcyBhIHJlc3VsdCBvZiB0aGUgaW1wbGljaXQgZmxvdy4gVGhlc2UgdG9rZW5zIGFyZVxuICAgICAqIHBhcnNlZCwgdmFsaWRhdGVkIGFuZCB1c2VkIHRvIHNpZ24gdGhlIHVzZXIgaW4gdG8gdGhlXG4gICAgICogY3VycmVudCBjbGllbnQuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25hbCBvcHRpb25zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgICAgIGxldCBwYXJ0czogb2JqZWN0O1xuXG4gICAgICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XG5cbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICAgICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcihvcHRpb25zLCBwYXJ0cyk7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcbiAgICAgICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSBwYXJ0c1snc2Vzc2lvbl9zdGF0ZSddO1xuICAgICAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyAob3IgYm90aCkgbXVzdCBiZSB0cnVlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5vaWRjICYmICFpZFRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcbiAgICAgICAgICAgICAgICAnd2VyZSBhY3RpdmF0ZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gYnV0IHRoZSBpZF90b2tlbiAnICtcbiAgICAgICAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrKSB7XG4gICAgICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG5cbiAgICAgICAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgICBudWxsLFxuICAgICAgICAgICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcbiAgICAgICAgICAgICAgICBncmFudGVkU2NvcGVzXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLm9pZGMpIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XG5cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3NJZFRva2VuKGlkVG9rZW4sIGFjY2Vzc1Rva2VuKVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy52YWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gb3B0aW9uc1xuICAgICAgICAgICAgICAgICAgICAgICAgLnZhbGlkYXRpb25IYW5kbGVyKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW46IHJlc3VsdC5pZFRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRlOiBzdGF0ZVxuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuKF8gPT4gcmVzdWx0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG4gICAgICAgICAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xuICAgICAgICAgICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2gocmVhc29uID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcml2YXRlIHBhcnNlU3RhdGUoc3RhdGU6IHN0cmluZyk6IFtzdHJpbmcsIHN0cmluZ10ge1xuICAgICAgICBsZXQgbm9uY2UgPSBzdGF0ZTtcbiAgICAgICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xuXG4gICAgICAgIGlmIChzdGF0ZSkge1xuICAgICAgICAgICAgY29uc3QgaWR4ID0gc3RhdGUuaW5kZXhPZih0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yKTtcbiAgICAgICAgICAgIGlmIChpZHggPiAtMSkge1xuICAgICAgICAgICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XG4gICAgICAgICAgICAgICAgdXNlclN0YXRlID0gc3RhdGUuc3Vic3RyKGlkeCArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IubGVuZ3RoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gW25vbmNlLCB1c2VyU3RhdGVdO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZU5vbmNlKFxuICAgICAgICBub25jZUluU3RhdGU6IHN0cmluZ1xuICAgICk6IGJvb2xlYW4ge1xuICAgICAgICBjb25zdCBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgICAgICBpZiAoc2F2ZWROb25jZSAhPT0gbm9uY2VJblN0YXRlKSB7XG4gICAgICAgICAgICBcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdWYWxpZGF0aW5nIGFjY2Vzc190b2tlbiBmYWlsZWQsIHdyb25nIHN0YXRlL25vbmNlLic7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbicsIGlkVG9rZW4uaWRUb2tlbik7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdzZXNzaW9uX3N0YXRlJywgc2Vzc2lvblN0YXRlKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0U2Vzc2lvblN0YXRlKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcbiAgICAgICAgaWYgKG9wdGlvbnMub25Mb2dpbkVycm9yKSB7XG4gICAgICAgICAgICBvcHRpb25zLm9uTG9naW5FcnJvcihwYXJ0cyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQGlnbm9yZVxuICAgICAqL1xuICAgIHB1YmxpYyBwcm9jZXNzSWRUb2tlbihcbiAgICAgICAgaWRUb2tlbjogc3RyaW5nLFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICBza2lwTm9uY2VDaGVjayA9IGZhbHNlXG4gICAgKTogUHJvbWlzZTxQYXJzZWRJZFRva2VuPiB7XG4gICAgICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xuICAgICAgICBjb25zdCBoZWFkZXJKc29uID0gYjY0RGVjb2RlVW5pY29kZShoZWFkZXJCYXNlNjQpO1xuICAgICAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xuICAgICAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcbiAgICAgICAgY29uc3QgY2xhaW1zSnNvbiA9IGI2NERlY29kZVVuaWNvZGUoY2xhaW1zQmFzZTY0KTtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcbiAgICAgICAgY29uc3Qgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcblxuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xuICAgICAgICAgICAgaWYgKGNsYWltcy5hdWQuZXZlcnkodiA9PiB2ICE9PSB0aGlzLmNsaWVudElkKSkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQuam9pbignLCcpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZDtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWNsYWltcy5zdWIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICAvKiBGb3Igbm93LCB3ZSBvbmx5IGNoZWNrIHdoZXRoZXIgdGhlIHN1YiBhZ2FpbnN0XG4gICAgICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cbiAgICAgICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXG4gICAgICAgICAqIGluIGV2ZXJ5IG90aGVyIGNhc2UgdG9vLlxuICAgICAgICAgKi9cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9XG4gICAgICAgICAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcbiAgICAgICAgICAgICAgICBgRXhwZWN0ZWQgc3ViOiAke3RoaXMuc2lsZW50UmVmcmVzaFN1YmplY3R9LCByZWNlaXZlZCBzdWI6ICR7XG4gICAgICAgICAgICAgICAgY2xhaW1zWydzdWInXVxuICAgICAgICAgICAgICAgIH1gO1xuXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghY2xhaW1zLmlhdCkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ05vIGlhdCBjbGFpbSBpbiBpZF90b2tlbic7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBpc3N1ZXI6ICcgKyBjbGFpbXMuaXNzO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXNraXBOb25jZUNoZWNrICYmIGNsYWltcy5ub25jZSAhPT0gc2F2ZWROb25jZSkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIG5vbmNlOiAnICsgY2xhaW1zLm5vbmNlO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiZcbiAgICAgICAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXG4gICAgICAgICAgICAhY2xhaW1zWydhdF9oYXNoJ11cbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnQW4gYXRfaGFzaCBpcyBuZWVkZWQhJztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgaXNzdWVkQXRNU2VjID0gY2xhaW1zLmlhdCAqIDEwMDA7XG4gICAgICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcbiAgICAgICAgY29uc3QgY2xvY2tTa2V3SW5NU2VjID0gKHRoaXMuY2xvY2tTa2V3SW5TZWMgfHwgNjAwKSAqIDEwMDA7XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgaXNzdWVkQXRNU2VjIC0gY2xvY2tTa2V3SW5NU2VjID49IG5vdyB8fFxuICAgICAgICAgICAgZXhwaXJlc0F0TVNlYyArIGNsb2NrU2tld0luTVNlYyA8PSBub3dcbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnVG9rZW4gaGFzIGV4cGlyZWQnO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnIpO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcih7XG4gICAgICAgICAgICAgICAgbm93OiBub3csXG4gICAgICAgICAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXG4gICAgICAgICAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMgPSB7XG4gICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgICAgandrczogdGhpcy5qd2tzLFxuICAgICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgICAgbG9hZEtleXM6ICgpID0+IHRoaXMubG9hZEp3a3MoKVxuICAgICAgICB9O1xuXG5cbiAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcylcbiAgICAgICAgICAudGhlbihhdEhhc2hWYWxpZCA9PiB7XG4gICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgICAgICAgICB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJlxuICAgICAgICAgICAgICAhYXRIYXNoVmFsaWRcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgICAgICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xuICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHJlY2VpdmVkIGNsYWltcyBhYm91dCB0aGUgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0SWRlbnRpdHlDbGFpbXMoKTogb2JqZWN0IHtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIGlmICghY2xhaW1zKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0R3JhbnRlZFNjb3BlcygpOiBvYmplY3Qge1xuICAgICAgICBjb25zdCBzY29wZXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgICAgIGlmICghc2NvcGVzKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShzY29wZXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2VcbiAgICAgICAgICAgID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHBhZEJhc2U2NChiYXNlNjRkYXRhKTogc3RyaW5nIHtcbiAgICAgICAgd2hpbGUgKGJhc2U2NGRhdGEubGVuZ3RoICUgNCAhPT0gMCkge1xuICAgICAgICAgICAgYmFzZTY0ZGF0YSArPSAnPSc7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJhc2U2NGRhdGE7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgY3VycmVudCBhY2Nlc3NfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldEFjY2Vzc1Rva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuJylcbiAgICAgICAgICAgIDogbnVsbDtcbiAgICB9XG5cbiAgICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cbiAgICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGlkX3Rva2VuXG4gICAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2tlcywgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGFjY2Vzc190b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaGFzVmFsaWRBY2Nlc3NUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGhhc1ZhbGlkSWRUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgYXV0aC1oZWFkZXIgdGhhdCBjYW4gYmUgdXNlZFxuICAgICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXG4gICAgICovXG4gICAgcHVibGljIGF1dGhvcml6YXRpb25IZWFkZXIoKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmVzIGFsbCB0b2tlbnMgYW5kIGxvZ3MgdGhlIHVzZXIgb3V0LlxuICAgICAqIElmIGEgbG9nb3V0IHVybCBpcyBjb25maWd1cmVkLCB0aGUgdXNlciBpc1xuICAgICAqIHJlZGlyZWN0ZWQgdG8gaXQuXG4gICAgICogQHBhcmFtIG5vUmVkaXJlY3RUb0xvZ291dFVybFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2dPdXQobm9SZWRpcmVjdFRvTG9nb3V0VXJsID0gZmFsc2UpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWRfdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3JlZnJlc2hfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2V4cGlyZXNfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gbnVsbDtcblxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcblxuICAgICAgICBpZiAoIXRoaXMubG9nb3V0VXJsKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFpZF90b2tlbiAmJiAhdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBsb2dvdXRVcmw6IHN0cmluZztcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ291dFVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnbG9nb3V0VXJsIG11c3QgdXNlIGh0dHBzLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IHJlcXVpcmVIdHRwcyBtdXN0IGFsbG93IGh0dHAnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRm9yIGJhY2t3YXJkIGNvbXBhdGliaWxpdHlcbiAgICAgICAgaWYgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJ3t7JykgPiAtMSkge1xuICAgICAgICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7aWRfdG9rZW5cXH1cXH0vLCBpZF90b2tlbilcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xuXG4gICAgICAgICAgICBpZiAoaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW4pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBwb3N0TG9nb3V0VXJsID0gdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgICAgIGlmIChwb3N0TG9nb3V0VXJsKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgncG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpJywgcG9zdExvZ291dFVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGxvZ291dFVybCA9XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dvdXRVcmwgK1xuICAgICAgICAgICAgICAgICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgK1xuICAgICAgICAgICAgICAgIHBhcmFtcy50b1N0cmluZygpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuY29uZmlnLm9wZW5VcmkobG9nb3V0VXJsKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlTm9uY2UoKS50aGVuKGZ1bmN0aW9uIChub25jZTogYW55KSB7XG4gICAgICAgICAgICB0aGF0Ll9zdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xuICAgICAgICAgICAgcmV0dXJuIG5vbmNlO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIG5nT25EZXN0cm95KCkge1xuICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNyZWF0ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMucm5nVXJsKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8qXG4gICAgICAgICAgICAgKiBUaGlzIGFscGhhYmV0IHVzZXMgYS16IEEtWiAwLTkgXy0gc3ltYm9scy5cbiAgICAgICAgICAgICAqIFN5bWJvbHMgb3JkZXIgd2FzIGNoYW5nZWQgZm9yIGJldHRlciBnemlwIGNvbXByZXNzaW9uLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBjb25zdCB1cmwgPSAnVWludDhBcmRvbVZhbHVlc09iajAxMjM0NTY3OUJDREVGR0hJSktMTU5QUVJTVFdYWVpfY2ZnaGtwcXZ3eHl6LSc7XG4gICAgICAgICAgICBsZXQgc2l6ZSA9IDQ1O1xuICAgICAgICAgICAgbGV0IGlkID0gJyc7XG5cbiAgICAgICAgICAgIGNvbnN0IGNyeXB0byA9IHNlbGYuY3J5cHRvIHx8IHNlbGZbJ21zQ3J5cHRvJ107XG4gICAgICAgICAgICBpZiAoY3J5cHRvKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgYnl0ZXMgPSBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KHNpemUpKTtcbiAgICAgICAgICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgICAgICAgICAgICBpZCArPSB1cmxbYnl0ZXNbc2l6ZV0gJiA2M107XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgICAgICAgICAgICBpZCArPSB1cmxbTWF0aC5yYW5kb20oKSAqIDY0IHwgMF07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXNvbHZlKGlkKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjaGVja1NpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgc2lnbmF0dXJlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zKTtcbiAgICB9XG5cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0IHRoZSBpbXBsaWNpdCBmbG93IG9yIHRoZSBjb2RlIGZsb3csXG4gICAgICogZGVwZW5kaW5nIG9uIHlvdXIgY29uZmlndXJhdGlvbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdExvZ2luRmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKSB7XG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5pbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuaW5pdEltcGxpY2l0RmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTdGFydHMgdGhlIGF1dGhvcml6YXRpb24gY29kZSBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMgbG9naW4gdXJsLlxuICAgICAqL1xuICAgIHB1YmxpYyBpbml0Q29kZUZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcbiAgICAgICAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcykpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBpbml0Q29kZUZsb3dJbnRlcm5hbChcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKTogdm9pZCB7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignbG9naW5VcmwgbXVzdCB1c2UgSHR0cC4gQWxzbyBjaGVjayBwcm9wZXJ0eSByZXF1aXJlSHR0cHMuJyk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgJycsIG51bGwsIGZhbHNlLCBwYXJhbXMpXG4gICAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0QXV0aG9yaXphdGlvbkNvZGVGbG93Jyk7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTogUHJvbWlzZTxbc3RyaW5nLCBzdHJpbmddPiB7XG5cbiAgICAgICAgaWYgKCF0aGlzLmNyeXB0bykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdQS0NJIHN1cHBvcnQgZm9yIGNvZGUgZmxvdyBuZWVkcyBhIENyeXB0b0hhbmRlci4gRGlkIHlvdSBpbXBvcnQgdGhlIE9BdXRoTW9kdWxlIHVzaW5nIGZvclJvb3QoKSA/Jyk7XG4gICAgICAgIH1cblxuXG4gICAgICAgIGNvbnN0IHZlcmlmaWVyID0gYXdhaXQgdGhpcy5jcmVhdGVOb25jZSgpO1xuICAgICAgICBjb25zdCBjaGFsbGVuZ2VSYXcgPSBhd2FpdCB0aGlzLmNyeXB0by5jYWxjSGFzaCh2ZXJpZmllciwgJ3NoYS0yNTYnKTtcbiAgICAgICAgY29uc3QgY2hhbGxhbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XG5cbiAgICAgICAgcmV0dXJuIFtjaGFsbGFuZ2UsIHZlcmlmaWVyXTtcbiAgICB9XG59XG4iXX0=