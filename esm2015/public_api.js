/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
export { OAuthModule } from './angular-oauth-oidic.module';
export { OAuthService } from './oauth-service';
export { JwksValidationHandler } from './token-validation/jwks-validation-handler';
export { NullValidationHandler } from './token-validation/null-validation-handler';
export { ValidationHandler, AbstractValidationHandler } from './token-validation/validation-handler';
export { UrlHelperService } from './url-helper.service';
export { AuthConfig } from './auth.config';
export { LoginOptions, OAuthLogger, OAuthStorage, ReceivedTokens } from './types';
export { AUTH_CONFIG } from './tokens';
export { OAuthEvent, OAuthSuccessEvent, OAuthInfoEvent, OAuthErrorEvent } from './events';
export { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
export { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
export { OAuthModuleConfig, OAuthResourceServerConfig } from './oauth-module.config';
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicHVibGljX2FwaS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJwdWJsaWNfYXBpLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSw0QkFBYyw4QkFBOEIsQ0FBQztBQUM3Qyw2QkFBYyxpQkFBaUIsQ0FBQztBQUNoQyxzQ0FBYyw0Q0FBNEMsQ0FBQztBQUMzRCxzQ0FBYyw0Q0FBNEMsQ0FBQztBQUMzRCw2REFBYyx1Q0FBdUMsQ0FBQztBQUN0RCxpQ0FBYyxzQkFBc0IsQ0FBQztBQUNyQywyQkFBYyxlQUFlLENBQUM7QUFDOUIsd0VBQWMsU0FBUyxDQUFDO0FBQ3hCLDRCQUFjLFVBQVUsQ0FBQztBQUN6QiwrRUFBYyxVQUFVLENBQUM7QUFDekIsd0NBQWMsMENBQTBDLENBQUM7QUFDekQscUZBQWMsOENBQThDLENBQUM7QUFDN0QsNkRBQWMsdUJBQXVCLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgKiBmcm9tICcuL2FuZ3VsYXItb2F1dGgtb2lkaWMubW9kdWxlJztcclxuZXhwb3J0ICogZnJvbSAnLi9vYXV0aC1zZXJ2aWNlJztcclxuZXhwb3J0ICogZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL2p3a3MtdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuZXhwb3J0ICogZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL251bGwtdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuZXhwb3J0ICogZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XHJcbmV4cG9ydCAqIGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuZXhwb3J0ICogZnJvbSAnLi9hdXRoLmNvbmZpZyc7XHJcbmV4cG9ydCAqIGZyb20gJy4vdHlwZXMnO1xyXG5leHBvcnQgKiBmcm9tICcuL3Rva2Vucyc7XHJcbmV4cG9ydCAqIGZyb20gJy4vZXZlbnRzJztcclxuZXhwb3J0ICogZnJvbSAnLi9pbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvcic7XHJcbmV4cG9ydCAqIGZyb20gJy4vaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyJztcclxuZXhwb3J0ICogZnJvbSAnLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcclxuIl19