import { InterfaceFunction } from "@antelopejs/interface-core";
import type { IncomingMessage, ServerResponse } from "node:http";
import { SetParameterProvider } from "@antelopejs/interface-api";
import { MakeParameterAndPropertyAndClassDecorator } from "@antelopejs/interface-core/decorators";

const AuthHeaderName = "x-antelopejs-auth";
const AuthCookieName = "ANTELOPEJS_AUTH";
const EmptyString = "";
const CookieOptionSeparator = "; ";
const ClassParameterProviderSymbolDescription = "authentication-class-provider";

/**
 * A value JSON can represent: a string, number, boolean, `null`, an array of
 * JSON values, or a {@link JsonObject}. `Date`, `Buffer`, functions and class
 * instances are not JSON values; convert them first (for example
 * `date.toISOString()`).
 */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | JsonObject;

/**
 * String keys mapped to JSON values. A key whose value is `undefined` is
 * accepted so an optional field can be passed as is; `JSON.stringify` drops
 * it. An object typed as an `interface` is not assignable (it has no index
 * signature); declare it with a `type` alias or spread it into a literal.
 */
export type JsonObject = { [key: string]: JsonValue | undefined };

/**
 * What a verified token yields: the signed string, or the JSON object that was
 * signed. The shape inside the object is not checked by the interface; read it
 * through a parser of your own (see {@link AuthVerifier}).
 */
export type AuthClaims = string | JsonObject;

/**
 * Function type that extracts authentication data from HTTP request.
 *
 * @param req - The incoming HTTP request
 * @param res - The server response object
 * @returns The authentication token string or undefined if not found
 *
 * @example
 * ```typescript
 * const headerSource: AuthSource = (req) => req.headers['authorization']?.replace('Bearer ', '');
 * ```
 */
export type AuthSource = (
  req: IncomingMessage,
  res: ServerResponse,
) => string | undefined;
/**
 * Function type that verifies authentication data and returns parsed content.
 *
 * @template T - The type of the verified data
 * @param data - The authentication data to verify
 * @param options - Optional verification parameters
 * @returns The verified data or a Promise resolving to the verified data
 *
 * @example
 * ```typescript
 * const sessionVerifier: AuthVerifier<UserProfile> = async (token, options) =>
 *   parseUserProfile(await ValidateRaw(token, options));
 * ```
 */
export type AuthVerifier<T = AuthClaims> = (
  data?: string,
  options?: VerifyOptions,
) => Promise<T> | T;
/**
 * Function type that performs additional validation on verified authentication data.
 *
 * @template T - The type of input data to validate
 * @template R - The type of the validation result
 * @param data - The verified data to validate
 * @returns The validation result or a Promise resolving to the validation result
 *
 * @example
 * ```typescript
 * const roleValidator: AuthValidator<UserProfile, boolean> = (profile) =>
 *   profile.roles.includes('admin');
 * ```
 */
export type AuthValidator<T = AuthClaims, R = unknown> = (
  data: T,
) => Promise<R> | R;

/**
 * HTTP Cookie options for controlling how authentication cookies are set.
 *
 * Keys are serialized literally. False and undefined values are omitted;
 * true values become standalone directives, and other values use String(value).
 * No attributes are supplied by default.
 *
 * @property maxAge - Serialized as maxAge, not the standard Max-Age attribute
 * @property signed - Serialized as a directive; does not add a cookie signature
 * @property expires - Serialized with String(date), not an HTTP-date formatter
 * @property httpOnly - Whether the cookie is only accessible via HTTP(S) and not client JavaScript
 * @property path - URL path for which the cookie is valid
 * @property domain - Domain for which the cookie is valid
 * @property secure - Whether the cookie should only be sent over HTTPS
 *
 * @example
 * ```typescript
 * const secureOptions: CookieOptions = {
 *   httpOnly: true,
 *   secure: true,
 *   path: '/'
 * };
 * ```
 */
export interface CookieOptions {
  maxAge?: number;
  signed?: boolean;
  expires?: Date;
  httpOnly?: boolean;
  path?: string;
  domain?: string;
  secure?: boolean;
}

type TimeSpanUnit =
  | "Years"
  | "Year"
  | "Yrs"
  | "Yr"
  | "Y"
  | "Weeks"
  | "Week"
  | "W"
  | "Days"
  | "Day"
  | "D"
  | "Hours"
  | "Hour"
  | "Hrs"
  | "Hr"
  | "H"
  | "Minutes"
  | "Minute"
  | "Mins"
  | "Min"
  | "M"
  | "Seconds"
  | "Second"
  | "Secs"
  | "Sec"
  | "s"
  | "Milliseconds"
  | "Millisecond"
  | "Msecs"
  | "Msec"
  | "Ms";

/**
 * A timespan string in the grammar of the `ms` package: a number, optionally
 * followed by a unit in any case, with or without a space (`"90"`, `"2h"`,
 * `"7 days"`). A bare number string counts milliseconds.
 */
export type TimeSpan =
  | `${number}`
  | `${number}${TimeSpanUnit | Uppercase<TimeSpanUnit> | Lowercase<TimeSpanUnit>}`
  | `${number} ${TimeSpanUnit | Uppercase<TimeSpanUnit> | Lowercase<TimeSpanUnit>}`;

/**
 * Options for signing authentication tokens.
 *
 * @property expiresIn - Duration until the token expires, as seconds or timespan string (e.g. '1h', '2d')
 * @property notBefore - Duration before which the token is not valid, as seconds or timespan string
 *
 * @example
 * ```typescript
 * const tokenOptions: SignOptions = {
 *   expiresIn: '2h', // Token valid for 2 hours
 *   notBefore: '5s'  // Token not valid until 5 seconds after issuance
 * };
 * ```
 */
export interface SignOptions {
  /**
   * Expiration as a number of seconds or a {@link TimeSpan}.
   */
  expiresIn?: number | TimeSpan;

  /**
   * Not-before field as a number of seconds or a {@link TimeSpan}.
   */
  notBefore?: number | TimeSpan;
}

/**
 * Options for verifying authentication tokens.
 *
 * @property ignoreExpiration - If true, expired tokens will still be considered valid
 * @property ignoreNotBefore - If true, tokens that are not yet valid will still be considered valid
 * @property maxAge - Maximum age of the token, as seconds or timespan string
 *
 * @example
 * ```typescript
 * const verifyOptions: VerifyOptions = {
 *   ignoreExpiration: false,
 *   maxAge: '30m'  // Reject tokens older than 30 minutes
 * };
 * ```
 */
export interface VerifyOptions {
  /**
   * Ignore signature expiration.
   */
  ignoreExpiration?: boolean;

  /**
   * Ignore signature not-before field.
   */
  ignoreNotBefore?: boolean;

  /**
   * Maximum signature age as a number of seconds or a timespan string.
   */
  maxAge?: string | number;
}

/**
 * What a token signs: a string, a `Buffer`, or a {@link JsonObject}.
 */
export type AuthPayload = string | Buffer | JsonObject;
type VerifyInterfaceHandler = (
  data?: string,
  options?: VerifyOptions,
) => Promise<AuthClaims>;
type SignInterfaceHandler = (
  data: AuthPayload,
  options?: SignOptions,
) => Promise<string>;
type AuthParameterProvider<T, R> = (
  context: AuthenticationContext,
) => Promise<T | R>;

interface AuthenticationContext {
  rawRequest: IncomingMessage;
  rawResponse: ServerResponse;
}

interface AuthDecoratorOptions<T, R> {
  source?: AuthSource;
  authenticatorOptions?: VerifyOptions;
  validator?: AuthValidator<T, R>;
}

interface DefaultAuthDecoratorCallbacks<R> extends AuthDecoratorOptions<
  AuthClaims,
  R
> {
  authenticator?: undefined;
}

interface CustomAuthDecoratorCallbacks<T, R> extends AuthDecoratorOptions<
  T,
  R
> {
  authenticator: AuthVerifier<T>;
}

interface ResolvedAuthDecoratorCallbacks<T, R> {
  source: AuthSource;
  authenticator: AuthVerifier<T>;
  authenticatorOptions: VerifyOptions;
  validator: AuthValidator<T, R> | undefined;
}

function readAuthHeader(req: IncomingMessage): string | undefined {
  const header = req.headers[AuthHeaderName];
  if (Array.isArray(header)) {
    return header[0];
  }

  return header;
}

function readCookieToken(req: IncomingMessage): string | undefined {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return undefined;
  }

  const cookieMatch = ` ${cookieHeader}`.match(/ ANTELOPEJS_AUTH=([^;]*)/);
  return cookieMatch?.[1];
}

function serializeCookieOptions(cookieOptions?: CookieOptions): string {
  if (!cookieOptions) {
    return EmptyString;
  }

  const entries = Object.entries(cookieOptions).filter(
    ([, value]) => value !== undefined && value !== false,
  );
  if (entries.length === 0) {
    return EmptyString;
  }

  return entries
    .map(([key, value]) => (value === true ? key : `${key}=${String(value)}`))
    .join(CookieOptionSeparator);
}

function createSetCookieHeader(
  token: string,
  cookieOptions?: CookieOptions,
): string {
  const serializedCookieOptions = serializeCookieOptions(cookieOptions);
  if (!serializedCookieOptions) {
    return `${AuthCookieName}=${token}`;
  }

  return `${AuthCookieName}=${token}; ${serializedCookieOptions}`;
}

function resolveAuthDecoratorCallbacks<T, R>(
  options: AuthDecoratorOptions<T, R>,
  authenticator: AuthVerifier<T>,
): ResolvedAuthDecoratorCallbacks<T, R> {
  return {
    source: options.source ?? internal.defaultSource,
    authenticator,
    authenticatorOptions: options.authenticatorOptions ?? {},
    validator: options.validator,
  };
}

function createAuthParameterProvider<T, R>(
  callbacks: ResolvedAuthDecoratorCallbacks<T, R>,
  validator?: AuthValidator<T, R>,
): AuthParameterProvider<T, R> {
  return (context: AuthenticationContext) =>
    internal.CheckAuthentication(context.rawRequest, context.rawResponse, {
      ...callbacks,
      validator,
    });
}

function buildAuthDecorator<T, R>(
  callbacks: ResolvedAuthDecoratorCallbacks<T, R>,
) {
  return MakeParameterAndPropertyAndClassDecorator(
    (target, key, index, validator?: AuthValidator<T, R>) => {
      const authValidator = validator ?? callbacks.validator;
      const provider = createAuthParameterProvider(callbacks, authValidator);

      if (key === undefined) {
        SetParameterProvider(
          target.prototype,
          Symbol(ClassParameterProviderSymbolDescription),
          undefined,
          provider,
        );
        return;
      }

      SetParameterProvider(target, key, index, provider);
    },
  );
}

type AuthDecoratorFactory<T, R> = ReturnType<typeof buildAuthDecorator<T, R>>;

/**
 * @internal
 */
export namespace internal {
  export const Verify = InterfaceFunction<VerifyInterfaceHandler>();
  export const Sign = InterfaceFunction<SignInterfaceHandler>();

  export function defaultSource(
    req: IncomingMessage,
    _res: ServerResponse,
  ): string | undefined {
    return readAuthHeader(req) ?? readCookieToken(req);
  }

  export const defaultAuthenticator: AuthVerifier = ValidateRaw;

  /**
   * Verifies the signature of signed data attached to the HTTP request and returns the data contained therein.
   *
   * @template T - The type of data after verification
   * @template R - The type of data after validation
   * @param req - HTTP Request
   * @param res - HTTP Response
   * @param callbacks - The source, the authenticator with its options, and the optional validator, all already resolved
   * @returns The authenticated and validated data
   */
  export async function CheckAuthentication<T = AuthClaims, R = unknown>(
    req: IncomingMessage,
    res: ServerResponse,
    callbacks: ResolvedAuthDecoratorCallbacks<T, R>,
  ): Promise<T | R> {
    const { source, authenticator, authenticatorOptions, validator } =
      callbacks;
    const verifiedData = await authenticator(
      source(req, res),
      authenticatorOptions,
    );
    if (!validator) {
      return verifiedData;
    }

    return validator(verifiedData);
  }
}

/**
 * Verifies the signature of some signed data and returns the data contained therein.
 *
 * The result is the signed string or JSON object ({@link AuthClaims}). Its shape is
 * not checked: parse it into the type you expect before relying on a field.
 *
 * @param token - The signed data token to verify
 * @param options - Options for verification
 * @returns A promise resolving to the verified data
 *
 * @example
 * ```typescript
 * const claims = await ValidateRaw(authToken, { maxAge: '1h' });
 * const user = parseUserProfile(claims);
 * console.log(user.name);
 * ```
 */
export function ValidateRaw(
  token?: string,
  options?: VerifyOptions,
): Promise<AuthClaims> {
  return internal.Verify(token, options);
}

/**
 * Signs some data to create an authentication token.
 *
 * @param data - The data to sign
 * @param options - Options for signing
 * @returns The signed data token
 *
 * @example
 * ```typescript
 * const token = SignRaw({ userId: 123, role: 'admin' }, { expiresIn: '24h' });
 * ```
 */
export function SignRaw(
  data: AuthPayload,
  options?: SignOptions,
): Promise<string> {
  return internal.Sign(data, options);
}

/**
 * Signs some data and attaches it to an HTTP Response object as a cookie.
 * Replaces the Set-Cookie header with ANTELOPEJS_AUTH and the supplied attributes.
 * Does not send or end the response. See {@link CookieOptions} for serialization limits.
 *
 * @param res - HTTP Response object to set the cookie on
 * @param data - Data to sign and attach
 * @param signOptions - Options for signing the data
 * @param cookieOptions - Options for the cookie
 * @returns A promise that resolves when the cookie has been set
 *
 * @example
 * ```typescript
 * await SignServerResponse(
 *   res,
 *   { userId: 123, permissions: ['read', 'write'] },
 *   { expiresIn: '8h' },
 *   { httpOnly: true, secure: true }
 * );
 * ```
 */
export function SignServerResponse(
  res: ServerResponse,
  data: AuthPayload,
  signOptions?: SignOptions,
  cookieOptions?: CookieOptions,
): Promise<ServerResponse> {
  return SignRaw(data, signOptions).then((token) => {
    res.setHeader("Set-Cookie", createSetCookieHeader(token, cookieOptions));
    return res;
  });
}

/**
 * Creates a Parameter Provider using the specified source and signature verification callbacks.
 *
 * The callbacks are processed in the following order:
 * `source(req, res)` => `authenticator(prev, authenticatorOptions)` => `validator(prev)` => Parameter
 * A validator must throw to deny access; its return value is injected unchanged.
 * A validator passed to the decorator replaces the configured validator.
 *
 * Without `authenticator`, the default one calls {@link ValidateRaw} and the validator
 * receives an {@link AuthClaims}. With an `authenticator`, `T` is whatever it returns,
 * so a parser written there gives the validator a typed value.
 *
 * @template T - The type of the authenticated data before validation
 * @template R - The type of the final validator result
 * @param callbacks - Configuration object containing callback functions
 * @param callbacks.source - Extracts the signed data from the request
 * @param callbacks.authenticator - Verifies the signature
 * @param callbacks.authenticatorOptions - Options for verification
 * @param callbacks.validator - Custom validation step (overrideable with decorator call)
 * @returns A decorator for parameters, properties, and classes
 *
 * @example
 * ```typescript
 * import { Controller, Get } from '@antelopejs/interface-api';
 * import { CreateAuthDecorator } from '@antelopejs/interface-auth';
 *
 * // Create a custom auth decorator
 * const RequireAdmin = CreateAuthDecorator({
 *   validator: (claims) => {
 *     if (typeof claims === 'string' || claims.role !== 'admin') {
 *       throw new Error('Admin access required');
 *     }
 *     return claims;
 *   }
 * });
 *
 * // Use the decorator
 * class AdminController extends Controller('/admin') {
 *   @Get('settings')
 *   getSettings(@RequireAdmin() user: { role: string }) {
 *     // Only admin users can access this
 *     return { role: user.role };
 *   }
 * }
 * ```
 */
export function CreateAuthDecorator<R = unknown>(
  callbacks: DefaultAuthDecoratorCallbacks<R>,
): AuthDecoratorFactory<AuthClaims, R>;
export function CreateAuthDecorator<T, R = unknown>(
  callbacks: CustomAuthDecoratorCallbacks<T, R>,
): AuthDecoratorFactory<T, R>;
export function CreateAuthDecorator<T, R>(
  callbacks:
    | DefaultAuthDecoratorCallbacks<R>
    | CustomAuthDecoratorCallbacks<T, R>,
): AuthDecoratorFactory<AuthClaims, R> | AuthDecoratorFactory<T, R> {
  if (callbacks.authenticator) {
    return buildAuthDecorator(
      resolveAuthDecoratorCallbacks(callbacks, callbacks.authenticator),
    );
  }

  return buildAuthDecorator(
    resolveAuthDecoratorCallbacks(callbacks, ValidateRaw),
  );
}

/**
 * Parameter Provider using the default source and signature verification callbacks.
 * Reads the raw token from x-antelopejs-auth, falling back to ANTELOPEJS_AUTH
 * only when the header is absent. Does not read Authorization or strip Bearer.
 * This decorator can be applied to parameters, properties, or classes to
 * require authentication.
 *
 * @param validator - Optional custom validation callback
 * @returns The authenticated user data
 *
 * @example
 * ```typescript
 * import { Controller, Get } from '@antelopejs/interface-api';
 * import { Authentication } from '@antelopejs/interface-auth';
 *
 * class UserController extends Controller('/users') {
 *   @Get('profile')
 *   getProfile(@Authentication() user: { name: string; email: string }) {
 *     // 'user' contains the authenticated user data
 *     return { name: user.name, email: user.email };
 *   }
 * }
 * ```
 *
 * @see {@link CreateAuthDecorator}
 */
export const Authentication = CreateAuthDecorator({});
