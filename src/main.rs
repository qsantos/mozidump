use std::borrow::Cow;

use clap::Parser;
use json::JsonValue;

fn u8_slice_as_u16_slice(bytes: &[u8]) -> Cow<'_, [u16]> {
    assert!(bytes.len() % 2 == 0, "length must be even");

    let ptr = bytes.as_ptr();
    if ptr.align_offset(std::mem::align_of::<u16>()) == 0 {
        // Aligned: safe zero-copy cast
        let u16s = unsafe { std::slice::from_raw_parts(ptr as *const u16, bytes.len() / 2) };
        Cow::Borrowed(u16s)
    } else {
        // Not aligned: convert and allocate
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
            .collect();
        Cow::Owned(u16s)
    }
}

#[allow(dead_code)]
mod data_type {
    // Special values
    pub const FLOAT_MAX: u32 = 0xFFF00000;
    pub const HEADER: u32 = 0xFFF10000;

    // Basic JavaScript types
    pub const NULL: u32 = 0xFFFF0000;
    pub const UNDEFINED: u32 = 0xFFFF0001;
    pub const BOOLEAN: u32 = 0xFFFF0002;
    pub const INT32: u32 = 0xFFFF0003;
    pub const STRING: u32 = 0xFFFF0004;

    // Extended JavaScript types
    pub const DATE_OBJECT: u32 = 0xFFFF0005;
    pub const REGEXP_OBJECT: u32 = 0xFFFF0006;
    pub const ARRAY_OBJECT: u32 = 0xFFFF0007;
    pub const OBJECT_OBJECT: u32 = 0xFFFF0008;
    pub const ARRAY_BUFFER_OBJECT: u32 = 0xFFFF0009;
    pub const BOOLEAN_OBJECT: u32 = 0xFFFF000A;
    pub const STRING_OBJECT: u32 = 0xFFFF000B;
    pub const NUMBER_OBJECT: u32 = 0xFFFF000C;
    pub const BACK_REFERENCE_OBJECT: u32 = 0xFFFF000D;
    //DO_NOT_USE_1
    //DO_NOT_USE_2
    pub const TYPED_ARRAY_OBJECT: u32 = 0xFFFF0010;
    pub const MAP_OBJECT: u32 = 0xFFFF0011;
    pub const SET_OBJECT: u32 = 0xFFFF0012;
    pub const END_OF_KEYS: u32 = 0xFFFF0013;
    //DO_NOT_USE_3
    pub const DATA_VIEW_OBJECT: u32 = 0xFFFF0015;
    pub const SAVED_FRAME_OBJECT: u32 = 0xFFFF0016; // ?

    // Principals ?
    pub const JSPRINCIPALS: u32 = 0xFFFF0017;
    pub const NULL_JSPRINCIPALS: u32 = 0xFFFF0018;
    pub const RECONSTRUCTED_SAVED_FRAME_PRINCIPALS_IS_SYSTEM: u32 = 0xFFFF0019;
    pub const RECONSTRUCTED_SAVED_FRAME_PRINCIPALS_IS_NOT_SYSTEM: u32 = 0xFFFF001A;

    // ?
    pub const SHARED_ARRAY_BUFFER_OBJECT: u32 = 0xFFFF001B;
    pub const SHARED_WASM_MEMORY_OBJECT: u32 = 0xFFFF001C;

    // Arbitrarily sized integers
    pub const BIGINT: u32 = 0xFFFF001D;
    pub const BIGINT_OBJECT: u32 = 0xFFFF001E;

    // Older typed arrays
    pub const TYPED_ARRAY_V1_MIN: u32 = 0xFFFF0100;
    pub const TYPED_ARRAY_V1_INT8: u32 = TYPED_ARRAY_V1_MIN;
    pub const TYPED_ARRAY_V1_UINT8: u32 = TYPED_ARRAY_V1_MIN + 1;
    pub const TYPED_ARRAY_V1_INT16: u32 = TYPED_ARRAY_V1_MIN + 2;
    pub const TYPED_ARRAY_V1_UINT16: u32 = TYPED_ARRAY_V1_MIN + 3;
    pub const TYPED_ARRAY_V1_INT32: u32 = TYPED_ARRAY_V1_MIN + 4;
    pub const TYPED_ARRAY_V1_UINT32: u32 = TYPED_ARRAY_V1_MIN + 5;
    pub const TYPED_ARRAY_V1_FLOAT32: u32 = TYPED_ARRAY_V1_MIN + 6;
    pub const TYPED_ARRAY_V1_FLOAT64: u32 = TYPED_ARRAY_V1_MIN + 7;
    pub const TYPED_ARRAY_V1_UINT8_CLAMPED: u32 = TYPED_ARRAY_V1_MIN + 8;
    pub const TYPED_ARRAY_V1_MAX: u32 = TYPED_ARRAY_V1_UINT8_CLAMPED;

    // Transfer-only tags (not used for persistent data)
    pub const TRANSFER_MAP_HEADER: u32 = 0xFFFF0200;
    pub const TRANSFER_MAP_PENDING_ENTRY: u32 = 0xFFFF0201;
    pub const TRANSFER_MAP_ARRAY_BUFFER: u32 = 0xFFFF0202;
    pub const TRANSFER_MAP_STORED_ARRAY_BUFFER: u32 = 0xFFFF0203;
}

struct MozSerialDecoder<'a> {
    // data to decode
    input: &'a [u8],
    // index of the next thing to decode in the input
    pos: usize,
}

impl<'a> MozSerialDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        MozSerialDecoder { input, pos: 0 }
    }

    fn peek_u32(&self) -> u32 {
        u32::from_le_bytes(self.input[self.pos..self.pos + 4].try_into().unwrap())
    }

    fn peek_next_u32(&self) -> u32 {
        u32::from_le_bytes(self.input[self.pos + 4..self.pos + 8].try_into().unwrap())
    }

    fn peek_pair(&self) -> (u32, u32) {
        let data = self.peek_u32();
        let tag = self.peek_next_u32();
        (tag, data)
    }

    fn read_bytes(&mut self, count: usize) -> &[u8] {
        let ret = &self.input[self.pos..self.pos + count];
        self.pos += count.next_multiple_of(8); // handles padding
        ret
    }

    fn read_u32(&mut self) -> u32 {
        let res = self.peek_u32();
        self.pos += 4;
        res
    }

    fn read_pair(&mut self) -> (u32, u32) {
        let data = self.read_u32();
        let tag = self.read_u32();
        (tag, data)
    }

    fn read_header(&mut self) {
        let (tag, _data) = self.peek_pair();
        if tag == data_type::HEADER {
            self.read_pair();
        }
    }

    fn read_transfer_map(&mut self) {
        let (tag, _data) = self.peek_pair();
        assert_ne!(tag, data_type::TRANSFER_MAP_HEADER);
    }

    fn read_string_value(&mut self, data: u32) -> JsonValue {
        let length: usize = (data & 0x7FFFFFFF).try_into().unwrap();
        let is_latin1 = (data & 0x80000000) != 0;
        let string = if is_latin1 {
            let bytes = self.read_bytes(length);
            String::from_utf8(bytes.to_vec()).unwrap() // TODO: actual latin1
        } else {
            let bytes = self.read_bytes(length * 2);
            let shorts = u8_slice_as_u16_slice(bytes);
            String::from_utf16(shorts.as_ref()).unwrap()
        };
        JsonValue::String(string)
    }

    fn read_bigint(&mut self) -> JsonValue {
        unimplemented!("bigint")
    }

    fn read_value(&mut self) -> JsonValue {
        let (tag, data) = self.read_pair();
        match tag {
            0..data_type::FLOAT_MAX => {
                let bytes = ((tag as u64) << 32) | (data as u64);
                let float = f64::from_bits(bytes);
                JsonValue::Number(float.into())
            }
            data_type::NULL => JsonValue::Null,
            data_type::UNDEFINED => JsonValue::Null, // TODO
            data_type::INT32 => {
                let data = data as i32;
                JsonValue::Number(data.into())
            }
            data_type::BOOLEAN | data_type::BOOLEAN_OBJECT => JsonValue::Boolean(data != 0),
            data_type::STRING | data_type::STRING_OBJECT => self.read_string_value(data),
            data_type::BIGINT | data_type::BIGINT_OBJECT => self.read_bigint(),
            data_type::DATE_OBJECT => unimplemented!("date"),
            data_type::REGEXP_OBJECT => unimplemented!("regexp"),
            data_type::ARRAY_OBJECT => {
                let mut vec = Vec::new();
                loop {
                    let key = self.read_value();
                    if key == JsonValue::Null {
                        break;
                    }
                    let JsonValue::Number(key) = key else {
                        panic!()
                    };
                    let key = key.as_fixed_point_u64(0).unwrap() as usize;
                    let value = self.read_value();
                    if key >= vec.len() {
                        vec.resize(key + 1, JsonValue::Null);
                    }
                    vec[key] = value;
                }
                JsonValue::Array(vec)
            }
            data_type::OBJECT_OBJECT => {
                let mut obj = json::object::Object::new();
                loop {
                    let key = self.read_value();
                    if key == JsonValue::Null {
                        break;
                    }
                    let JsonValue::String(key) = key else {
                        panic!()
                    };
                    let value = self.read_value();
                    obj.insert(&key, value);
                }
                JsonValue::Object(obj)
            }
            data_type::BACK_REFERENCE_OBJECT => unimplemented!("back reference"),
            data_type::MAP_OBJECT => unimplemented!("map"),
            data_type::SET_OBJECT => unimplemented!("set"),
            data_type::END_OF_KEYS => JsonValue::Null, // TODO: need sentinel to support Set object
            datatype => unimplemented!("unimplemented datatype {datatype:#X}"),
        }
    }
}

fn read_document(input: &[u8]) -> JsonValue {
    let mut decoder = MozSerialDecoder::new(input);
    decoder.read_header();
    decoder.read_transfer_map();
    decoder.read_value()
}

#[test]
fn test() {
    let mut decoder = snap::raw::Decoder::new();
    let input = b"\xA8\x05\x04\x03\x00\x01\x01\x04\xF1\xFF\x01\x06\x34\x08\x00\xFF\xFF\x02\x00\x00\x80\x04\x00\xFF\xFF\x69\x64\x01\x12\x08\x00\x00\x24\x0D\x10\xA0\x30\x30\x30\x32\x65\x38\x37\x62\x2D\x30\x36\x33\x63\x2D\x34\x64\x34\x30\x2D\x61\x35\x33\x34\x2D\x31\x30\x33\x39\x64\x35\x62\x64\x36\x66\x61\x31\x00\x00\x00\x00\x07\x0D\x30\x20\x73\x74\x61\x72\x74\x65\x64\x00\x18\x0D\x10\x60\x32\x30\x32\x33\x2D\x31\x32\x2D\x31\x32\x54\x31\x38\x3A\x31\x33\x3A\x33\x32\x2E\x30\x31\x34\x5A\x08\x0D\x20\x1C\x66\x69\x6E\x69\x73\x68\x65\x64\x66\x30\x00\x18\x34\x2E\x31\x36\x35\x5A\x0A\x0D\x30\x24\x63\x6F\x70\x69\x65\x64\x54\x65\x78\x74\x09\xA8\x00\x01\x0D\x18\x00\x2C\x09\x0F\x15\x88\x18\x6D\x69\x73\x74\x61\x6B\x65\x05\x16\x01\xE0\x00\x11\x0D\x28\x40\x65\x78\x70\x65\x63\x74\x65\x64\x43\x68\x61\x72\x61\x63\x74\x65\x72\x05\x22\x04\x00\x00\x11\x48\x00\x37\x0D\x10\x11\x30\x0D\x48\x00\x6E\x5E\x30\x00\x00\x7A\x0D\x30\x01\x01\x0C\x13\x00\xFF\xFF\x11\xD8\x1C\x73\x65\x74\x74\x69\x6E\x67\x73\x01\x18\x10\x08\x00\xFF\xFF\x03\x0D\x80\x08\x77\x70\x6D\x01\x13\x24\x00\x1E\x00\x00\x00\x03\x00\xFF\xFF\x04\x0D\x18\x08\x74\x6F\x6E\x05\xAD\x04\x58\x02\x09\x18\x11\xF0\x14\x65\x72\x72\x6F\x72\x5F\x11\x1E\x08\x00\x00\xC8\x0D\x38\x00\x0B\x0D\x38\x2C\x77\x6F\x72\x64\x5F\x6C\x65\x6E\x67\x74\x68\x00\x01\x01\x00\x05\x0D\x20\x00\x07\x0D\x20\x20\x63\x68\x61\x72\x73\x65\x74\x00\x29\x0D\x10\xA0\x4B\x4D\x55\x52\x45\x53\x4E\x41\x50\x54\x4C\x57\x49\x2E\x4A\x5A\x3D\x46\x4F\x59\x2C\x56\x47\x35\x2F\x51\x39\x32\x48\x33\x38\x42\x3F\x34\x37\x43\x31\x44\x36\x30\x58\x01\x4D\x0D\x01\x01\xD8\x11\x50\x20\x65\x6C\x61\x70\x73\x65\x64\x00\x01\x0D\x68\x00\x10\x0D\x58\x29\x98\x35\x26\x00\x73\x11\x20\x00\x05\x0D\x20\x0C\x73\x63\x6F\x72\x01\xE1\x11\x18\x00\x0C\x0D\x18\x09\x38\x10\x47\x72\x6F\x75\x70\x25\x2C\x01\x01\x2C\x03\x00\xFF\xFF\x00\x00\x00\x00\x13\x00\xFF\xFF";
    let output_len = snap::raw::decompress_len(input).unwrap();
    let mut output = vec![0; output_len];
    decoder.decompress(input, &mut output).unwrap();

    let value = read_document(&output);
    use json::object;
    assert_eq!(
        value,
        object! {
            id: "0002e87b-063c-4d40-a534-1039d5bd6fa1",
            started: "2023-12-12T18:13:32.014Z",
            finished: "2023-12-12T18:13:34.165Z",
            copiedText: ",",
            mistake: object! {
                expectedCharacter: "7",
                mistakenCharacter: "z"
            },
            settings: object! {
                wpm: 30,
                tone: 600,
                error_tone: 200,
                word_length: 5,
                charset: "KMURESNAPTLWI.JZ=FOY,VG5/Q92H38B?47C1D60X"
            },
            elapsed: 1,
            copiedCharacters: 1,
            score: 1,
            copiedGroups: 0
        }
    );
}

#[derive(Parser, Debug)]
struct Args {
    database: String,
}

fn main() {
    let args = Args::parse();

    let conn = rusqlite::Connection::open(&args.database).unwrap();

    let mut stmt = conn.prepare("SELECT id, name FROM object_store").unwrap();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        println!("{row:?}");
    }

    let mut stmt = conn
        .prepare("SELECT object_store_id, data FROM object_data")
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut output = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let rusqlite::types::ValueRef::Blob(data) = row.get_ref(1).unwrap() else {
            panic!();
        };

        let mut decoder = snap::raw::Decoder::new();
        let output_len = snap::raw::decompress_len(data).unwrap();
        if output_len > output.len() {
            output.resize(output_len, 0);
        }
        decoder.decompress(data, &mut output).unwrap();

        let value = read_document(&output[..output_len]);
        //println!("{value:?}");
    }
}
