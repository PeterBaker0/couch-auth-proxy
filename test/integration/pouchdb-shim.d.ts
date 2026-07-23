declare module "pouchdb" {
  import type { EventEmitter } from "node:events";

  export interface Database {
    allDocs(opts?: object): Promise<{ rows: Array<{ id: string }> }>;
    get<T = Record<string, unknown>>(id: string): Promise<T>;
    put(doc: object): Promise<{ ok: boolean; id: string; rev: string }>;
    remove(doc: object): Promise<{ ok: boolean }>;
    replicate: {
      from(remote: Database | string, opts?: object): Promise<ReplicationResult> & EventEmitter;
      to(remote: Database | string, opts?: object): Promise<ReplicationResult> & EventEmitter;
    };
    sync(
      remote: Database | string,
      opts?: object,
    ): Promise<SyncResult> & EventEmitter & { cancel(): void };
    close(): Promise<void>;
  }

  export interface ReplicationResult {
    ok: boolean;
    docs_written: number;
    docs_read?: number;
    doc_write_failures?: number;
    errors?: unknown[];
  }

  export interface SyncResult {
    push: ReplicationResult;
    pull: ReplicationResult;
  }

  interface PouchDBConstructor {
    new (
      name: string,
      opts?: {
        adapter?: string;
        auth?: { username: string; password: string };
        /** When true, do not auto-create the remote database. */
        skip_setup?: boolean;
        fetch?: (url: string | Request, opts?: RequestInit) => Promise<Response>;
      },
    ): Database;
    plugin(plugin: unknown): void;
    fetch(url: string | Request, opts?: RequestInit): Promise<Response>;
  }

  const PouchDB: PouchDBConstructor;
  export default PouchDB;
}

declare module "pouchdb-adapter-memory" {
  const memory: unknown;
  export default memory;
}
