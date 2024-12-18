use crypto::der::{ Oid, AsnType::*, AsnBitString };

#[test]
fn test() {
    let magic = Sequence(vec![
        Sequence(vec![
            ObjectIdentifier(Oid(vec![2, 16, 840, 1, 101, 3, 4, 1, 4]))
        ]),
        BitString(AsnBitString { bits: vec![120, 10], unused: 0 })
    ]);
    println!("{:?}", to_hex(&magic.serialise()));
}

fn to_hex(message: &[u8]) -> String {
    message.iter().map(|byte| format!("{byte:02x}")).collect()
}