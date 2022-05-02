export declare type Options = {
    rethinkIdBaseUri?: string;
    appId: string;
    signUpRedirectUri: string;
    logInRedirectUri: string;
    onLogInComplete: () => void;
};
export declare type Permission = {
    id: string;
    tableName: string;
    userId: string;
    permission: string;
};
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
