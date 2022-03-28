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
        data: object;
    }>;
    subscribe(methodOptions: {}, listener: SubscribeListener): Promise<() => Promise<{
        message: string;
    }>>;
    insert(row: object, methodOptions?: {}): Promise<{
        message: string;
    }>;
    update(row: object, methodOptions?: {}): Promise<{
        message: string;
    }>;
    replace(methodOptions?: {}): Promise<{
        message: string;
    }>;
    delete(methodOptions?: {
        rowId?: string;
    }): Promise<{
        message: string;
    }>;
}
