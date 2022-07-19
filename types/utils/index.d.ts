/**
 * Generates a secure random string using the browser crypto functions
 */
export declare function generateRandomString(): string;
/**
 * Return the base64-url encoded sha256 hash for the PKCE challenge
 * @param codeVerifier A random string
 */
export declare function pkceChallengeFromVerifier(codeVerifier: string): Promise<string>;
/**
 * Open and center pop-up on specific window to account for multiple monitors
 * @param url url to open
 * @param windowName name to identify pop-up window
 * @param win the parent/opener window
 * @param w width
 * @param h height
 * @returns `Window` if successful, `null` if blocked by a built-in browser pop-up blocker. Otherwise fails silently I think...
 */
export declare function popUpWindow(url: string, windowName: string, win: Window, w: number, h: number): Window | null;
