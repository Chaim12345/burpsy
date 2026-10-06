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
}

export function decodeProtobuf(bodyBase64: string, grpc: boolean): Promise<ProtoDecodeResponse> {
 return api<ProtoDecodeResponse>("/api/protobuf/decode", json("POST", { body_base64: bodyBase64, grpc }));
}

export function encodeProtobuf(grpc: boolean, frames: ProtoFrame[]): Promise<{ body_base64: string }> {
 return api<{ body_base64: string }>("/api/protobuf/encode", json("POST", { grpc, frames }));
}
