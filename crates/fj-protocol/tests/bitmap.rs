//! Bitmap tests: run-length roundtrips, missing ranges, corruption.

use fj_protocol::ErrorCode;
use fj_protocol::bitmap::Bitmap;
use proptest::prelude::*;

#[test]
fn basics() {
    let mut b = Bitmap::new(200);
    assert_eq!(b.count_ones(), 0);
    assert!(!b.is_full());
    b.set(0, true);
    b.set(199, true);
    b.set(200, true); // out of range ignored
    assert_eq!(b.count_ones(), 2);
    assert_eq!(b.to_runs(), [(0, 1), (199, 1)]);
    assert_eq!(b.missing_ranges(10), [(1, 198)]);
    assert!(b.get(0) && b.get(199) && !b.get(5));
    let mut z = Bitmap::new(0);
    assert!(z.is_full(), "empty bitmap is vacuously full");
    z.set(0, true); // ignored
    assert_eq!(z.to_runs(), []);
}

#[test]
fn corrupt_runs() {
    assert_eq!(
        Bitmap::from_runs(10, &[(5, 2), (1, 2)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    assert_eq!(
        Bitmap::from_runs(10, &[(1, 3), (2, 1)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    assert_eq!(
        Bitmap::from_runs(10, &[(0, 0)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    assert_eq!(
        Bitmap::from_runs(5, &[(0, 6)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    assert_eq!(
        Bitmap::from_runs(5, &[(6, 1)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    let mut b = Bitmap::new(5);
    assert_eq!(
        b.merge_runs(&[(9, 1)]).unwrap_err().code(),
        ErrorCode::BitmapCorrupt
    );
    // adjacent (touching, non-overlapping) runs are fine
    assert!(Bitmap::from_runs(10, &[(0, 5), (5, 5)]).unwrap().is_full());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn runs_roundtrip(len in 1u64..300u64, set in proptest::collection::vec(any::<u64>(), 0..500) ) {
        let mut b = Bitmap::new(len);
        for raw in set {
            b.set(raw % len, true);
        }
        let runs = b.to_runs();
        let back = Bitmap::from_runs(len, &runs).unwrap();
        prop_assert_eq!(back.to_runs(), runs);
        prop_assert_eq!(back.count_ones(), b.count_ones());
        prop_assert_eq!(back.is_full(), b.is_full());
        // missing_ranges is the exact complement
        let miss = back.missing_ranges(usize::MAX);
        let mut total: u64 = back.count_ones();
        total += miss.iter().map(|(_, l)| l).sum::<u64>();
        prop_assert_eq!(total, len);
        // next_missing lists ascending unset indices
        let all = back.next_missing(0, usize::MAX);
        for w in all.windows(2) {
            prop_assert!(w[0] < w[1]);
        }
        prop_assert_eq!(all.len() as u64, len - back.count_ones());
    }
}
