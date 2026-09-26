use super::*;

#[test]
fn restores_valid_fake_entries_alongside_legacy_url_label() {
    let resolver = Resolver::new(Dns::default(), std::sync::Arc::new(meta_platform::DefaultHooks));
    let valid_ip = resolver.fake_address("persist.test", false).unwrap();
    let mut entries = resolver.export_fake();
    entries.push((r"https\:\/\/im.dingtalk.com".into(), "198.18.0.35".parse().unwrap()));
    let next = Resolver::new(Dns::default(), std::sync::Arc::new(meta_platform::DefaultHooks));
    next.import_fake(&entries).unwrap();
    assert_eq!(next.original(valid_ip).as_deref(), Some("persist.test"));
    assert_eq!(next.export_fake().len(), 1);
    assert_eq!(next.fake_address("new.test", false).unwrap(), "198.18.0.36".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn url_label_in_wire_query_cannot_poison_fake_ip_profile() {
    let resolver = Resolver::new(Dns::default(), std::sync::Arc::new(meta_platform::DefaultHooks));
    let name = Name::from_labels([b"https://im".as_slice(), b"dingtalk", b"com"]).unwrap();
    let mut query = Message::new();
    query.set_id(87).add_query(Query::query(name, RecordType::A));
    let response = Message::from_vec(&resolver.answer(&query.to_vec().unwrap()).await.unwrap()).unwrap();
    assert_eq!(response.id(), 87);
    assert_eq!(response.response_code(), ResponseCode::FormErr);
    assert!(resolver.export_fake().is_empty());
}
use hickory_proto::rr::rdata::SOA;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn request(name: &str, id: u16) -> Message {
    let mut request = Message::new();
    request
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    request
}

#[tokio::test]
async fn dot_uses_dns_tcp_framing_inside_tls_stream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let query = request("dot.test.", 77);
    let mut response = query.clone();
    response.set_message_type(hickory_proto::op::MessageType::Response);
    let expected = query.to_vec().unwrap();
    let reply = response.to_vec().unwrap();
    let (client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        let length = server.read_u16().await.unwrap() as usize;
        let mut received = vec![0; length];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_u16(reply.len() as u16).await.unwrap();
        server.write_all(&reply).await.unwrap();
    });
    let received = Resolver::exchange_stream(client, &query).await.unwrap();
    assert_eq!(received.id(), 77);
    task.await.unwrap();
}

#[tokio::test]
async fn policy_proxy_resolver_hosts_and_fake_persistence() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap().to_string();
        let mut config = Dns {
            ipv6: false,
            nameserver: vec!["127.0.0.1:1".into()],
            proxy_server_nameserver: vec![address.clone()],
            ..Dns::default()
        };
        config
            .nameserver_policy
            .insert("+.policy.test".into(), meta_config::Strings::One(address));
        let hooks: meta_platform::Hooks = Arc::new(meta_platform::DefaultHooks);
        let resolver = Resolver::new(config.clone(), hooks.clone());
        let mut hosts = std::collections::BTreeMap::new();
        hosts.insert(
            "local.test".into(),
            meta_config::Strings::One("192.0.2.8".into()),
        );
        hosts.insert(
            "alias.test".into(),
            meta_config::Strings::One("local.test".into()),
        );
        resolver
            .configure(&hosts, &crate::resources::Resources::default())
            .unwrap();
        let server = tokio::spawn(async move {
            let mut b = [0u8; 4096];
            for _ in 0..2 {
                let (n, peer) = udp.recv_from(&mut b).await.unwrap();
                let mut reply = Message::from_vec(&b[..n]).unwrap();
                let name = reply.queries()[0].name().clone();
                reply.set_message_type(MessageType::Response);
                reply.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(A("192.0.2.9".parse().unwrap())),
                ));
                udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        assert_eq!(
            resolver.lookup("x.policy.test", 443).await.unwrap()[0],
            "192.0.2.9:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolver.lookup_proxy("node.other.test", 443).await.unwrap()[0],
            "192.0.2.9:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolver.lookup("alias.test", 80).await.unwrap()[0],
            "192.0.2.8:80".parse::<SocketAddr>().unwrap()
        );
        let host_answer = Message::from_vec(
            &resolver
                .answer(&request("local.test", 1).to_vec().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            host_answer.answers()[0].data(),
            &RData::A(A("192.0.2.8".parse().unwrap()))
        );
        let fake = resolver.fake_address("persist.test", false).unwrap();
        let saved = resolver.export_fake();
        let next = Resolver::new(config, hooks);
        next.import_fake(&saved).unwrap();
        assert_eq!(next.original(fake).as_deref(), Some("persist.test"));
        assert_eq!(next.fake_address("persist.test", false).unwrap(), fake);
        assert_ne!(next.fake_address("new.test", false).unwrap(), fake);
        assert!(
            next.import_fake(&[("bad.test".into(), "8.8.8.8".parse().unwrap())])
                .is_err()
        );
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lookup_and_bootstrap_accept_names_without_final_dot() {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap().to_string();
    let resolver = Resolver::new(
        Dns {
            nameserver: vec![address.clone()],
            default_nameserver: vec![address],
            ipv6: false,
            ..Dns::default()
        },
        Arc::new(meta_platform::DefaultHooks),
    );
    let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for _ in 0..2 {
            let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let mut reply = Message::from_vec(&buffer[..n]).unwrap();
            let name = reply.queries()[0].name().clone();
            reply.set_message_type(MessageType::Response);
            reply.add_answer(Record::from_rdata(
                name,
                60,
                RData::A(A("192.0.2.9".parse().unwrap())),
            ));
            udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        }
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        assert_eq!(
            resolver.lookup("echo.test", 443).await.unwrap(),
            vec!["192.0.2.9:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            resolver.bootstrap("dns.test", 853).await.unwrap(),
            "192.0.2.9:853".parse::<SocketAddr>().unwrap()
        );
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cache_preserves_negative_answers_ttls_and_query_flags() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for negative in [false, true] {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let config = Dns {
                nameserver: vec![udp.local_addr().unwrap().to_string()],
                enhanced_mode: "redir-host".into(),
                ipv6: false,
                ..Dns::default()
            };
            let count = Arc::new(AtomicUsize::new(0));
            let received = count.clone();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let mut buffer = [0; 4096];
                loop {
                    let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
                    let mut reply = Message::from_vec(&buffer[..n]).unwrap();
                    received.fetch_add(1, Ordering::Relaxed);
                    reply
                        .set_message_type(MessageType::Response)
                        .set_recursion_available(true);
                    if negative {
                        reply.set_response_code(ResponseCode::NXDomain);
                        reply.add_name_server(Record::from_rdata(
                            Name::from_ascii("test").unwrap(),
                            60,
                            RData::SOA(SOA::new(
                                Name::from_ascii("ns.test").unwrap(),
                                Name::from_ascii("hostmaster.test").unwrap(),
                                1,
                                60,
                                60,
                                60,
                                10,
                            )),
                        ));
                    } else {
                        reply.add_answer(Record::from_rdata(
                            reply.queries()[0].name().clone(),
                            30,
                            RData::A(A("192.0.2.1".parse().unwrap())),
                        ));
                    }
                    udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                }
            }));
            let resolver = Resolver::new(config, Arc::new(meta_platform::DefaultHooks));
            for id in [10, 20] {
                let reply = Message::from_vec(
                    &resolver
                        .answer(&request("cache.test", id).to_vec().unwrap())
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(reply.id(), id);
                assert_eq!(
                    reply.response_code(),
                    if negative {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NoError
                    }
                );
                assert_eq!(reply.name_servers().len(), usize::from(negative));
            }
            assert_eq!(count.load(Ordering::Relaxed), 1);
            assert_eq!(resolver.lookup("cache.test", 80).await.is_err(), negative);
            assert_eq!(count.load(Ordering::Relaxed), 1);
            for entry in resolver.cache.lock().unwrap().entries.values_mut() {
                entry.inserted -= Duration::from_secs(2);
            }
            let reply = Message::from_vec(
                &resolver
                    .answer(&request("cache.test", 30).to_vec().unwrap())
                    .await
                    .unwrap(),
            )
            .unwrap();
            let ttl = if negative {
                reply.name_servers()[0].ttl()
            } else {
                reply.answers()[0].ttl()
            };
            assert_eq!(ttl, if negative { 58 } else { 28 });
            let mut different = request("cache.test", 40);
            different.set_checking_disabled(true);
            resolver.answer(&different.to_vec().unwrap()).await.unwrap();
            assert_eq!(count.load(Ordering::Relaxed), 2);
            for entry in resolver.cache.lock().unwrap().entries.values_mut() {
                entry.expires = Instant::now();
            }
            resolver
                .answer(&request("cache.test", 50).to_vec().unwrap())
                .await
                .unwrap();
            assert_eq!(count.load(Ordering::Relaxed), 3);
            drop(server);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exhausted_fake_pools_fail_without_overflow_or_mapping_reuse() {
    for (v4, v6) in [
        (
            "255.255.255.254/31",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127",
        ),
        (
            "255.255.255.255/32",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
        ),
    ] {
        let resolver = Resolver::new(
            Dns {
                fake_ip_range: v4.parse().unwrap(),
                fake_ip_range6: v6.parse().unwrap(),
                ..Dns::default()
            },
            Arc::new(meta_platform::DefaultHooks),
        );
        for kind in [RecordType::A, RecordType::AAAA] {
            let mut query = request("exhausted.test", 1);
            query.queries_mut()[0].set_query_type(kind);
            let response =
                Message::from_vec(&resolver.answer(&query.to_vec().unwrap()).await.unwrap())
                    .unwrap();
            assert_eq!(response.response_code(), ResponseCode::ServFail);
        }
    }
    let resolver = Resolver::new(
        Dns {
            fake_ip_range: "198.18.0.0/30".parse().unwrap(),
            ..Dns::default()
        },
        Arc::new(meta_platform::DefaultHooks),
    );
    let allocated = resolver.fake_address("first.test", false).unwrap();
    assert!(resolver.fake_address("second.test", false).is_err());
    assert_eq!(resolver.original(allocated).as_deref(), Some("first.test"));
    assert_eq!(
        resolver.fake_address("first.test", false).unwrap(),
        allocated
    );
}
