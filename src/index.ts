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
 * const jwtVerifier: AuthVerifier<UserProfile> = (token) =>
 *   jwt.verify(token, SECRET_KEY) as UserProfile;
 * ```
 */
export type AuthVerifier<T = unknown> = (
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
export type AuthValidator<T = unknown, R = unknown> = (
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
   * Expiration as a number of seconds or a timespan string.
   */
  expiresIn?: string | number;

  /**
   * Not-before field as a number of seconds or a timespan string.
   */
  notBefore?: string | number;
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

type AuthPayload = string | Buffer | object;
type VerifyInterfaceHandler = (
  data?: string,
  options?: VerifyOptions,
) => Promise<Awaited<ReturnType<AuthVerifier>>>;
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

interface AuthDecoratorCallbacks<T, R> {
  source?: AuthSource;
  authenticator?: AuthVerifier<T>;
  authenticatorOptions?: VerifyOptions;
  validator?: AuthValidator<T, R>;
}

interface ResolvedAuthDecoratorCallbacks<T, R> {
  source: AuthSource;
  authenticator: AuthVerifier<T>;
  authenticatorOptions: VerifyOptions;
  validator: AuthValidator<T, R> | undefined;
}

interface ClassDecoratorTarget {
  prototype: object;
}

function readAuthHeader(req: IncomingMessage): string | undefined {
  const header = req.headers[AuthHeaderName];
  if (typeof header === "string") {
    return header;
  }

  if (!header || header.length === 0) {
    return undefined;
  }

  return header[0];
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
  callbacks: AuthDecoratorCallbacks<T, R>,
): ResolvedAuthDecoratorCallbacks<T, R> {
  return {
    source: callbacks.source ?? internal.defaultSource,
    authenticator: callbacks.authenticator ?? ValidateRaw,
    authenticatorOptions: callbacks.authenticatorOptions ?? {},
    validator: callbacks.validator,
  };
}

function createAuthParameterProvider<T, R>(
  callbacks: ResolvedAuthDecoratorCallbacks<T, R>,
  validator?: AuthValidator<T, R>,
): AuthParameterProvider<T, R> {
  return (context: AuthenticationContext) =>
    internal.CheckAuthentication(
      context.rawRequest,
      context.rawResponse,
      callbacks.source,
      callbacks.authenticator,
      callbacks.authenticatorOptions,
      validator,
    );
}

function registerClassParameterProvider<T, R>(
  target: ClassDecoratorTarget,
  provider: AuthParameterProvider<T, R>,
): void {
  SetParameterProvider(
    target.prototype,
    Symbol(ClassParameterProviderSymbolDescription),
    undefined,
    provider,
  );
}

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

  export const defaultAuthenticator: AuthVerifier<unknown> = ValidateRaw;

  /**
   * Verifies the signature of signed data attached to the HTTP request and returns the data contained therein.
   *
   * @template T - The type of data after verification
   * @template R - The type of data after validation
   * @param req - HTTP Request
   * @param res - HTTP Response
   * @param source - Callback to retrieve the signed data from the request
   * @param authenticator - Callback to verify the signature
   * @param authenticatorOptions - Verifier options
   * @param validator - Custom validator callback
   * @returns The authenticated and validated data
   */
  export async function CheckAuthentication<T = unknown, R = unknown>(
    req: IncomingMessage,
    res: ServerResponse,
    source: AuthSource = defaultSource,
    authenticator: AuthVerifier<T> = ValidateRaw,
    authenticatorOptions: VerifyOptions = {},
    validator?: AuthValidator<T, R>,
  ): Promise<T | R> {
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
 * @template T - The type of data expected after verification
 * @param token - The signed data token to verify
 * @param options - Options for verification
 * @returns A promise resolving to the verified data
 *
 * @example
 * ```typescript
 * const userData = await ValidateRaw<UserProfile>(authToken, { maxAge: '1h' });
 * console.log(userData.name);
 * ```
 */
export function ValidateRaw<T = unknown>(
  token?: string,
  options?: VerifyOptions,
): Promise<T> {
  return internal.Verify(token, options) as Promise<T>;
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
 * @template R - The type of the final validator result
 * @template T - The type of the authenticated data before validation
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
 *   validator: (user: any) => {
 *     if (!user || user.role !== 'admin') {
 *       throw new Error('Admin access required');
 *     }
 *     return user;
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
export function CreateAuthDecorator<R = unknown, T = unknown>(
  callbacks: AuthDecoratorCallbacks<T, R>,
) {
  const resolvedCallbacks = resolveAuthDecoratorCallbacks(callbacks);

  return MakeParameterAndPropertyAndClassDecorator(
    (target, key, index, validator?: AuthValidator<T, R>) => {
      const authValidator = validator ?? resolvedCallbacks.validator;
      const provider = createAuthParameterProvider(
        resolvedCallbacks,
        authValidator,
      );

      if (key === undefined) {
        registerClassParameterProvider(target, provider);
        return;
      }

      SetParameterProvider(target, key, index, provider);
    },
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
