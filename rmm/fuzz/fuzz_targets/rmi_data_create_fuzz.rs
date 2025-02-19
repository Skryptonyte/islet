#![no_main]

use islet_rmm::rmi::{DATA_CREATE_UNKNOWN, DATA_DESTROY, GRANULE_DELEGATE, GRANULE_UNDELEGATE, RTT_READ_ENTRY, SUCCESS};
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target, Corpus};

#[derive(Debug, arbitrary::Arbitrary)]
struct DataCreateFuzz {
    ipa: u64,
}

fuzz_target!(|data: DataCreateFuzz| -> Corpus {
    let rd = realm_create();
    let ipa = data.ipa as usize;
    let data = alloc_granule(IDX_DATA1);

    /* Reject IPAs which cannot be mapped */
    let ret = rmi::<RTT_READ_ENTRY>(&[rd, ipa, MAP_LEVEL]);
    if (ret[0] != SUCCESS) {
        realm_destroy(rd);
        return Corpus::Reject;
    }

    mock::host::map(rd, ipa);

    let _ret = rmi::<GRANULE_DELEGATE>(&[data]);

    let ret = rmi::<DATA_CREATE_UNKNOWN>(&[rd, data, ipa]);

    if ret[0] == SUCCESS {
        let _ret = rmi::<DATA_DESTROY>(&[rd, ipa]);
    }

    let _ret = rmi::<GRANULE_UNDELEGATE>(&[data]);

    mock::host::unmap(rd, ipa, false);
    realm_destroy(rd);

    Corpus::Keep
});
