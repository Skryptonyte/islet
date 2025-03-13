#![no_main]

use islet_rmm::rmi::{REC_ENTER, SUCCESS};
use islet_rmm::rsi::{PSCI_FEATURES};
use islet_rmm::rec::Rec;
use islet_rmm::rmi::rec::run::Run;
use islet_rmm::rec::context::set_reg;
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: u32| {
    let rd = mock::host::realm_setup();
    let feature = data as usize;

    let (rec1, run1) = (alloc_granule(IDX_REC1), alloc_granule(IDX_REC1_RUN));

    unsafe {
        let rec = &mut *(rec1 as *mut Rec<'_>);
        let run = &mut *(run1 as *mut Run);

        let _ret = rsi::<PSCI_FEATURES>(&[feature], rec, run);
    }

    mock::host::realm_teardown(rd);
});
