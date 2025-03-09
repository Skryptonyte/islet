#![no_main]

use islet_rmm::rmi::{RTT_SET_RIPAS, REC_ENTER, RTT_READ_ENTRY, SUCCESS};
use islet_rmm::rsi::IPA_STATE_SET;
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::{arbitrary, fuzz_target, Corpus};

#[derive(Debug, arbitrary::Arbitrary)]
struct RTTSetRIPASFuzz {
    base: u64,
    top: u64,

    ripas_state: u8,
    ripas_flags: u64,
}

fuzz_target!(|data: RTTSetRIPASFuzz| -> Corpus {
    let rd = mock::host::realm_setup();
    let base = data.base as usize;
    let top = data.top as usize;
    let ripas_state = data.ripas_state as usize;
    let ripas_flags = data.ripas_flags as usize;

    /* Reject IPAs which cannot be mapped */
    let ret = rmi::<RTT_READ_ENTRY>(&[rd, base, MAP_LEVEL]);
    if (ret[0] != SUCCESS) {
        mock::host::realm_teardown(rd);
        return Corpus::Reject;
    }

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    let _ret = rmi::<REC_ENTER>(&[rec1, run1]);

    unsafe {
        let rec = &mut *(rec1 as *mut Rec<'_>);
        let run = &mut *(run1 as *mut Run);

        let ret = rsi::<IPA_STATE_SET>(&[ripas_state, ripas_flags], rec, run);

        if ret[0] == SUCCESS {
            mock::host::map(rd, base);

            let ret = rmi::<RTT_SET_RIPAS>(&[rd, rec1, base, top]);

            mock::host::unmap(rd, base, false);
        }
    }

    mock::host::realm_teardown(rd);
    Corpus::Keep
});
