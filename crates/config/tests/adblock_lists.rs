//! Parses real downloaded lists: `ADBLOCK_LISTS=clash:a.yaml,adguard:b.txt
//! cargo test -p meta-config --release --test adblock_lists -- --ignored --nocapture`
use meta_config::{adblock::parse_list, rule::DomainSetBuilder};

#[test]
#[ignore]
fn parses_real_lists() {
    let lists = std::env::var("ADBLOCK_LISTS").expect("ADBLOCK_LISTS");
    for item in lists.split(',') {
        let (format, path) = item.split_once(':').unwrap();
        let data = std::fs::read(path).unwrap();
        let started = std::time::Instant::now();
        let (mut block, mut allow) = (DomainSetBuilder::default(), DomainSetBuilder::default());
        let taken = parse_list(&data, format, &mut block, &mut allow).unwrap();
        let (block, allow) = (block.build(), allow.build());
        println!(
            "{path}: {} KB, {taken} rules -> {} block / {} allow entries in {:?}",
            data.len() / 1024,
            block.len(),
            allow.len(),
            started.elapsed()
        );
        assert!(taken > 0);
    }
}
