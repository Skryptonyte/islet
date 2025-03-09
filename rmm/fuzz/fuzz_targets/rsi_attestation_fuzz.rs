#![no_main]

use islet_rmm::rmi::{RTT_READ_ENTRY, DATA_CREATE_UNKNOWN, DATA_DESTROY, RTT_INIT_RIPAS, REALM_ACTIVATE, GRANULE_DELEGATE, GRANULE_UNDELEGATE, SUCCESS};
use islet_rmm::rsi::{ATTEST_TOKEN_INIT, ATTEST_TOKEN_CONTINUE};
use islet_rmm::granule::GRANULE_SIZE;
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rec::context::get_reg;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target, Corpus};

#[derive(Debug, arbitrary::Arbitrary)]
struct AttestFuzz {
    ipa: u64,
    challenge: [u64; 8],
    offset: u64,
    size: u64
}

fuzz_target!(|data: AttestFuzz| -> Corpus {
    let ipa = data.ipa as usize;
    let challenge = &data.challenge;
    let offset = data.offset as usize;;
    let size = data.size as usize;;
    let top = match ipa.checked_add(L3_SIZE) {
        Some(x) => x,
        None => {
            return Corpus::Reject;
        }
    };

    let rd = mock::host::realm_unactivated_setup();
    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    let data_granule = alloc_granule(IDX_DATA1);
    let mut fuzz_ret = Corpus::Keep;

    /* Reject IPAs which cannot be mapped */
    let ret = rmi::<RTT_READ_ENTRY>(&[rd, ipa, MAP_LEVEL]);
    if ret[0] != SUCCESS {
        mock::host::realm_teardown(rd);
        return Corpus::Reject;
    }

    mock::host::map(rd, ipa);

    let ret = rmi::<RTT_INIT_RIPAS>(&[rd, ipa, top]);
    if ret[0] != SUCCESS {
        mock::host::unmap(rd, ipa, false);
        mock::host::realm_teardown(rd);
        return Corpus::Reject;
    }

    let ret = rmi::<REALM_ACTIVATE>(&[rd]);
    assert_eq!(ret[0], SUCCESS);

    let _ret = rmi::<GRANULE_DELEGATE>(&[data_granule]);

    let ret = rmi::<DATA_CREATE_UNKNOWN>(&[rd, data_granule, ipa]);
    if ret[0] == SUCCESS {

        unsafe {
            let rec = &mut *(rec1 as *mut Rec<'_>);
            let run = &mut *(run1 as *mut Run);

            let challenges = [
                challenge[0] as usize,
                challenge[1] as usize,
                challenge[2] as usize,
                challenge[3] as usize,
                challenge[4] as usize,
                challenge[5] as usize,
                challenge[6] as usize,
                challenge[7] as usize
            ];

            let _ret = rsi::<ATTEST_TOKEN_INIT>(&challenges, rec, run);

            let _ret = rsi::<ATTEST_TOKEN_CONTINUE>(&[ipa, offset, size], rec, run);
        }

        let ret = rmi::<DATA_DESTROY>(&[rd, ipa]);
        assert_eq!(ret[0], SUCCESS);
    } else {
        fuzz_ret = Corpus::Reject;
    }

    let _ret = rmi::<GRANULE_UNDELEGATE>(&[data_granule]);

    mock::host::unmap(rd, ipa, false);

    mock::host::realm_teardown(rd);

    fuzz_ret
});
