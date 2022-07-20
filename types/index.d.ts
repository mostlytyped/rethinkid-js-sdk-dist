import { Table } from "./table";
import { Options, Permission, SubscribeListener, MessageOrError } from "./types";
/**
 * The primary class of the RethinkID JS SDK to help you more easily build web apps with RethinkID.
 *
 * @example
 * ```
 * import RethinkID from "@mostlytyped/rethinkid-js-sdk";
 *
 * const config = {
 *   appId: "3343f20f-dd9c-482c-9f6f-8f6e6074bb81",
 *   loginRedirectUri: "https://example.com/complete-login",
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
     * Use {@link completeLogin} to exchange the authorization code for an access token and ID token
     * at the {@link Options.loginRedirectUri} URI specified when creating a RethinkID instance.
     *
     * @param callback After login callback, e.g. set logged in to true in local state. Redirect somewhere...
     */
    loginUri(callback?: () => void): Promise<string>;
    /**
     * Opens a pop-up window to perform OAuth login.
     * TODO enhance link with login URI, don't use alone
     */
    openLoginPopUp(url: string, event: Event): Promise<void>;
    /**
     * A "message" event listener for the login pop-up window.
     * Handles messages sent from the login pop-up window to its opener window.
     * @param event A postMessage event object
     */
    private _receiveLoginWindowMessage;
    /**
     * Completes the login flow.
     * Gets the access and ID tokens, establishes an API connection.
     *
     * Must be called at the {@link Options.loginRedirectUri} URI.
     */
    completeLogin(): Promise<void>;
    /**
     * Actions to take after login is complete
     *
     * 1. Establish a socket connection
     * 2. Run the user-defined login complete callback
     */
    private _afterLogin;
    /**
     * Takes an authorization code and exchanges it for an access token and ID token.
     * Used in {@link completeLogin}.
     * An authorization code is received as a URL param after a successfully calling {@link loginUri}
     * and approving the login request.
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
     * A utility function to check if a redirect to complete a login request has been performed.
     * Useful if a login redirect URI is not used solely to complete login, e.g. an app's
     * home page, to check when {@link completeLogin} needs to be called.
     *
     * Also used in {@link loginUri} to make sure PKCE local storage values are not overwritten,
     * which would otherwise accidentally invalidate a login request.
     */
    isLoggingIn(): boolean;
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
     * Create a table. Private endpoint.
     */
    tablesCreate(tableName: string): Promise<MessageOrError>;
    /**
     * Drop a table. Private endpoint.
     */
    tablesDrop(tableName: string): Promise<MessageOrError>;
    /**
     * List all table names. Private endpoint.
     * @returns Where `data` is an array of table names
     */
    tablesList(): Promise<{
        data: string[];
        error?: string;
    }>;
    /**
     * Get permissions for a table. Private endpoint.
     * @param options If no optional params are set, all permissions for the user are returned.
     * @returns All permissions are returned if no options are passed.
     */
    permissionsGet(options?: {
        tableName?: string;
        userId?: string;
        type?: "read" | "insert" | "update" | "delete";
    }): Promise<{
        data?: Permission[];
        error?: string;
    }>;
    /**
     * Set (insert/update) permissions for a table. Private endpoint.
     */
    permissionsSet(permissions: Permission[]): Promise<MessageOrError>;
    /**
     * Delete permissions for a table. Private endpoint.
     * @param options An optional object for specifying a permission ID to delete. All permissions are deleted if no permission ID option is passed.
     */
    permissionsDelete(options?: {
        permissionId?: string;
    }): Promise<MessageOrError>;
    /**
     * Read all table rows, or a single row if row ID passed. Private by default, or public with read permission.
     * @param options An optional object for specifying a row ID and/or user ID.
     * @returns Specify a row ID to get a specific row, otherwise all rows are returned. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableRead(tableName: string, options?: {
        rowId?: string;
        userId?: string;
    }): Promise<{
        data?: any[] | object;
        error?: string;
    }>;
    /**
     * Subscribe to table changes. Private by default, or public with read permission.
     * @param tableName
     * @param options An object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise passing `{}` operates on a table owned by the authenticated user.
     * @returns An unsubscribe function
     */
    tableSubscribe(tableName: string, options: {
        userId?: string;
    }, listener: SubscribeListener): Promise<() => Promise<MessageOrError>>;
    /**
     * Insert a table row, lazily creates the table if it does not exist. Private by default, or public with insert permission
     * @param tableName The name of the table to operate on.
     * @param row The row to insert.
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     * @returns Where `data` is the row ID
     */
    tableInsert(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<{
        data?: string;
        error?: string;
    }>;
    /**
     * Update all table rows, or a single row if row ID exists. Private by default, or public with update permission
     * @param tableName The name of the table to operate on.
     * @param row Note! If row.id not present, updates all rows
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableUpdate(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<MessageOrError>;
    /**
     * Replace a table row. Private by default, or public with insert, update, delete permissions.
     * @param tableName The name of the table to operate on.
     * @param row Must contain a row ID.
     * @param options An optional object for specifying a user ID. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableReplace(tableName: string, row: object, options?: {
        userId?: string;
    }): Promise<MessageOrError>;
    /**
     * Deletes all table rows, or a single row if row ID passed. Private by default, or public with delete permission.
     * @param tableName The name of the table to operate on.
     * @param options An optional object for specifying a row ID and/or user ID. Specify a row ID to delete a specific row, otherwise all rows are deleted. Specify a user ID to operate on a table owned by that user ID. Otherwise operates on a table owned by the authenticated user.
     */
    tableDelete(tableName: string, options?: {
        rowId?: string;
        userId?: string;
    }): Promise<MessageOrError>;
    table(tableName: string, tableOptions: {
        userId?: string;
    }): Table;
}
