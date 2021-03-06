/**
 * RethinkID constructor options
 */
export declare type Options = {
    rethinkIdBaseUri?: string;
    appId: string;
    /**
     * The URI the auth server redirects to with an auth code, after successful approving a login request.
     */
    loginRedirectUri: string;
    /**
     * Provide a callback to handled failed data API connections. E.g. unauthorized, or expired token.
     * `this` is the RethinkID instance. So you could log out with `this.logOut()` for example.
     */
    dataAPIConnectErrorCallback?: (errorMessage: string) => void;
};
export declare type Permission = {
    id?: string;
    tableName: string;
    userId: string;
    type: PermissionType;
};
export declare type PermissionType = "read" | "insert" | "update" | "delete";
export declare type LoginType = "popup_fallback" | "popup" | "redirect";
export declare type IdTokenDecoded = {
    at_hash: string;
    aud: string[];
    auth_time: number;
    exp: number;
    iat: number;
    iss: string;
    jti: string;
    rat: number;
    sid: string;
    sub: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
};
export declare type SubscribeListener = (changes: {
    new_val: object;
    old_val: object;
}) => void;
export declare type MessageOrError = {
    message?: string;
    error?: string;
};
