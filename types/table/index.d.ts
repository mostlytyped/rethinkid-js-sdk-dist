import RethinkID from "..";
import { SubscribeListener } from "../types";
export declare class Table {
    rid: RethinkID;
    tableName: string;
    tableOptions: {
        userId?: string;
    };
    constructor(rid: RethinkID, tableName: string, tableOptions: {
        userId?: string;
    });
    read(methodOptions?: {
        rowId?: string;
    }): Promise<{
        data?: object | any[];
        error?: string;
    }>;
    /**
     * @returns An unsubscribe function
     */
    subscribe(methodOptions: {}, listener: SubscribeListener): Promise<() => Promise<import("../types").MessageOrError>>;
    insert(row: object, methodOptions?: {}): Promise<{
        data?: string;
        error?: string;
    }>;
    update(row: object, methodOptions?: {}): Promise<import("../types").MessageOrError>;
    replace(methodOptions?: {}): Promise<import("../types").MessageOrError>;
    delete(methodOptions?: {
        rowId?: string;
    }): Promise<import("../types").MessageOrError>;
}
