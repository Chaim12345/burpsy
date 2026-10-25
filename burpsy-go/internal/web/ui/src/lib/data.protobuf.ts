// Protobuf / gRPC body decoding (burpsy-react-ui-3x2g), served by internal/web/api_protobuf.go at
// /api/protobuf/decode and /api/protobuf/encode (both POST, riskLocal — pure transforms).

import { api, json } from "./api";

/** One decoded protobuf field. Varint and i64 are decimal STRINGS because a uint64 exceeds JS's safe
 *  integer range and must not be rounded between the editor and the wire. */
export interface ProtoField {
 number: number;
 wire_type: number;
 varint?: string;
 i64?: string;
 i32?: number;
 len_kind?: "message" | "string" | "bytes";
 string?: string;
 bytes_hex?: string;
 message?: ProtoField[];
 /** Set when a .proto was supplied (burpsy-react-ui-3pco); presentation only — encode ignores them. */
 name?: string;
 type?: string;
 enum_name?: string;
}

export interface ProtoFrame {
 compressed?: boolean;
 trailer?: boolean;
 fields?: ProtoField[];
 text?: string;
 error?: string;
}

export interface ProtoDecodeResponse {
 grpc: boolean;
 frames: ProtoFrame[];
 /** With a .proto: every message it declares, and the one the fields were named against ("" when the
  *  schema has several and none was chosen or implied by the gRPC call path). */
 messages?: string[];
 message?: string;
 /** "reflection" when a TARGET supplied the schema over the network: adversary-controllable input, never
  *  to read as an operator's own .proto (47id). */
 schema_source?: string;
 /** The files the target served, when schema_source is "reflection". */
 schema_files?: string[];
}

/** What names the fields (burpsy-react-ui-3pco). All optional: without `proto` the decode is the
 *  schemaless numbers-and-wire-types view. `message` wins over the type a gRPC `rpc_path` implies. */
export interface ProtoSchemaOptions {
 proto?: string;
 message?: string;
 rpc_path?: string;
 direction?: "request" | "response";
}

export function decodeProtobuf(bodyBase64: string, grpc: boolean, schema: ProtoSchemaOptions = {}): Promise<ProtoDecodeResponse> {
 return api<ProtoDecodeResponse>("/api/protobuf/decode", json("POST", { body_base64: bodyBase64, grpc, ...schema }));
}

export function encodeProtobuf(grpc: boolean, frames: ProtoFrame[]): Promise<{ body_base64: string }> {
 return api<{ body_base64: string }>("/api/protobuf/encode", json("POST", { grpc, frames }));
}

/** The reflection opt-in (47id): the operator names the target and the service. POST /api/protobuf/reflect-decode
 *  is riskEgress: it dials the target once, clearing the engagement scope first, and carries no session credentials. */
export interface ProtoReflectTarget {
 target: string;
 service: string;
 tls: boolean;
}

export function reflectDecodeProtobuf(bodyBase64: string, grpc: boolean, reflect: ProtoReflectTarget): Promise<ProtoDecodeResponse> {
 return api<ProtoDecodeResponse>("/api/protobuf/reflect-decode", json("POST", { body_base64: bodyBase64, grpc, reflect }));
}
