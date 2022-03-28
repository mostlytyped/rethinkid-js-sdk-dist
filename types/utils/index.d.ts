/**
 * Generates a secure random string using the browser crypto functions
 */
export declare function generateRandomString(): string;
/**
 * Return the base64-url encoded sha256 hash for the PKCE challenge
 * @param codeVerifier A random string
 */
export declare function pkceChallengeFromVerifier(codeVerifier: string): Promise<string>;
