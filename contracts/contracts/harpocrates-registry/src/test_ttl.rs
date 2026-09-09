#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Events, vec, Env, IntoVal};

#[test]
fn test_extend_instance_ttl() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.extend_instance_ttl();

    let events = env.events().all();
    assert!(events.len() > 0);
    
    let last_event = events.last().unwrap();
    assert_eq!(last_event.0, contract_id);
    
    let topics: SorobanVec<Val> = last_event.1;
    assert_eq!(topics.len(), 2);
    
    let topic_0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
    let topic_1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    
    assert_eq!(topic_0, Symbol::new(&env, "ttl"));
    assert_eq!(topic_1, Symbol::new(&env, "instance"));
}

#[test]
fn test_extend_persistent_ttls() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.init(&admin);

    // Provide a list of keys to extend
    let keys = vec![
        &env,
        DataKey::Admin,
        DataKey::ProofTtl,
    ];

    client.extend_persistent_ttls(&keys);

    let events = env.events().all();
    
    let maintain_events: std::vec::Vec<_> = events.into_iter().filter(|e| {
        if e.0 != contract_id {
            return false;
        }
        let topics: SorobanVec<Val> = e.1.clone();
        if topics.len() != 2 {
            return false;
        }
        let topic_0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        let topic_1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
        topic_0 == Symbol::new(&env, "ttl") && topic_1 == Symbol::new(&env, "maintain")
    }).collect();

    assert_eq!(maintain_events.len(), 1);
    
    let event_data: TTLMaintained = maintain_events[0].2.clone().try_into_val(&env).unwrap();
    assert_eq!(event_data.count, 2);
}

#[test]
#[should_panic(expected = "HostError")]
fn test_extend_persistent_ttls_empty() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.extend_persistent_ttls(&vec![&env]);
}

#[test]
#[should_panic(expected = "HostError")]
fn test_extend_persistent_ttls_too_many() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let mut keys = vec![&env];
    for _ in 0..51 {
        keys.push_back(DataKey::ProofTtl);
    }

    client.extend_persistent_ttls(&keys);
}
