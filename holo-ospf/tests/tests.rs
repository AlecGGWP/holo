//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

mod conformance;
mod packet;

// HERE SOME TRY TO UNITEST   (LANCER AVEC : cargo +nightly test test_srv6_tlv_encode_decode -- --nocapture)  -> dans le repo : holo-ospf
#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use holo_ospf::packet::tlv::SRv6CapabilitiesTlv;

    #[test]
    fn test_srv6_tlv_encode_decode() {
        let original_tlv = SRv6CapabilitiesTlv {
            tlv_type: 20, 
            length: 4,
            flags: 0, 
            reserved: 0,  
        };

        let mut buf = BytesMut::new();
        original_tlv.encode(&mut buf);

        let decoded_tlv = SRv6CapabilitiesTlv::decode(original_tlv.length, &mut Bytes::from(buf)).unwrap();

        dbg!(&original_tlv);
        dbg!(&decoded_tlv);
        
        assert_eq!(original_tlv, decoded_tlv, "Erreur: {:?} != {:?}", original_tlv, decoded_tlv);
    }
}
