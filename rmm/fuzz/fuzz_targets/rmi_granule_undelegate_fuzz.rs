#![no_main]

use islet_rmm::rmi::{GRANULE_DELEGATE, GRANULE_UNDELEGATE, SUCCESS};
use islet_rmm::test_utils::{mock, *};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: u64| {
    let granule_addr = data as usize;

    let _ret = rmi::<GRANULE_UNDELEGATE>(&[granule_addr]);
});
