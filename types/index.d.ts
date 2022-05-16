import { Table } from "./table";
import { Options, Permission, SubscribeListener } from "./types";
/**
 * The primary class of the RethinkID JS SDK to help you more easily build web apps with RethinkID.
 *
 * @example
 * ```
 * import RethinkID from "@mostlytyped/rethinkid-js-sdk";
 *
 * const config = {
 *   appId: "3343f20f-dd9c-482c-9f6f-8f6e6074bb81",
 *   logInRedirectUri: "https://example.com/callback",
 * };
 *
 * export const rid = new RethinkID(config);
 * ```
 */
export default class RethinkID {
    constructor(options: Options);
    /**
     * Creates a SocketIO connection with an auth token
     */
    private _socketConnect;
    /**
     * Generate a URI to log in a user to RethinkID and authorize an app.
     * Uses the Authorization Code Flow for single page apps with PKCE code verification.
     * Requests an authorization code.
     *
     * Use {@link completeLogIn} to exchange the authorization code for an access token and ID token
     * at the {@link Options.logInRedirectUri} URI specified when creating a RethinkID instance.
     */
    logInUri(): Promise<string>;
    /**
     * Completes the log in flow.
     * Gets the access and ID tokens, establishes an API connection.
     *
     * Must be called at the {@link Options.logInRedirectUri} URI.
     */
    completeLogIn(): Promise<void>;
    /**
     * Takes an authorization code and exchanges it for an access token and ID token.
     * Used in {@link completeLogIn}.
     * An authorization code is received as a URL param after a successfully calling {@link logInUri}
     * and approving the log in request.
     *
     * Expects `code` and `state` query params to be present in the URL. Or else an `error` query
     * param if something went wrong.
     *
     * Stores the access token and ID token in local storage.
     */
    private _getAndSetTokens;
    /**
     * A utility function to check if the user is logged in.
     * i.e. if an access token and ID token are in local storage.
     */
    isLoggedIn(): boolean;
    /**
     * A utility function to log a user out.
     * Deletes the access token and ID token from local storage and reloads the page.
     */
    logOut(): void;
    /**
     * A utility function to get user info, i.e. user ID and the scope-based claims of an
     * authenticated user's ID token.
     */
    userInfo(): null | {
        id: string;
        email: string;
        name: string;
    };
    /**
     * Makes sure a socket has connected.
     */
    private _waitForConnection;
    /**
     * Promisifies a socket.io emit event
     * @param event A socket.io event name, like `tables:create`
     * @param payload
     */
    private _asyncEmit;
    /**
     * Creates a table
     */
    tablesCreate(tableName: string): Promise<{
        message: string;
    }>;
    /**
     * Drops, or deletes, a table
     */
    tablesDrop(tableName: string): Promise<{
        message: string;
    }>;
    /**
     * Lists all table names
     */
    tablesList(): Promise<{
        data: object;
    }>;
    /**
     * Gets permissions for a user.
     * @param options An optional object for specifying which permissions to get.
     * @returns All permissions are returned if no options are passed.
     */
    permissionsGet(options?: {
        tableName?: string;
        userId?: string;
        type?: "read" | "insert" | "update" | "delete";
    }): Promise<{
        data: Permission[];
    }>;
    /**
     * Sets permissions for a user
     */
    permissionsSet(permissions: Permission[]): Promise<{
        message: string;
    }>;
    /**
     * Deletes permissions for a user.
     * @param options An optional object for specifying a permission ID to delete. All permissions are deleted if no permission ID option is passed.
     */
    permissionsDelete(options?: {
        permissionId?: string;
    }): Promise<{
        message: string;
    }>;
    /**
     * Get data from a table.
     * @param options An optional object for specifying a row ID and/or user ID.
     * @returns Specify a row ID to get a specific row, otherwise all rows are returned. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableRead(tableName: string, options?: {
        rowId?: string;
        userId?: string;
    }): Promise<{
        data: object;
    }>;
    /**
     * Subscribe to table changes.
     * @param tableName
     * @param options An object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise passing `{}` operates on a table owned by the authenticated user.
     */
    tableSubscribe(tableName: string, options: {
        userId?: string;
    }, listener: SubscribeListener): Promise<() => Promise<{
        message: string;
    }>>;
    /**
     * Inserts a row into a table
     * @param tableName The name of the table to operate on.
     * @param row The row to insert.
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableInsert(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<{
        message: string;
    }>;
    /**
     * Updates a row in a table
     * @param tableName The name of the table to operate on.
     * @param row Must contain a row ID.
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableUpdate(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<{
        message: string;
    }>;
    /**
     * Replaces a row in a table
     * @param tableName The name of the table to operate on.
     * @param row Must contain a row ID.
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableReplace(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<{
        message: string;
    }>;
    /**
     * Deletes from a table
     * @param tableName The name of the table to operate on.
     * @param options An optional object for specifying a row ID and/or user ID. Specify a row ID to delete a specific row, otherwise all rows are deleted. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableDelete(tableName: string, options?: {
        rowId?: string;
        userId?: string;
    }): Promise<{
        message: string;
    }>;
    table(tableName: string, tableOptions: {
        userId?: string;
    }): Promise<Table>;
}
