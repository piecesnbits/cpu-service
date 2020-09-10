#include <cpuservice.hpp>

ACTION cpuservice::payerreg(name owner, name cpu_payer, name freecpu_permission, vector<name>require_recipients){
  require_auth(owner);
  check(is_account(cpu_payer), "cpu_payer isn't a valid account.");

  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto itr = _cpupayers.find(cpu_payer.value);
  check(itr == _cpupayers.end(), "cpu_payer already registered.");

  std::set<name> dup_recipients;
  for(name recipient : require_recipients){
    check(is_account(recipient), recipient.to_string()+" isn't a valid account.");
    check(dup_recipients.insert(recipient).second, "Duplicate recipient "+recipient.to_string() );
  }

  _cpupayers.emplace(owner, [&](auto& n) {
    n.cpu_payer = cpu_payer;
    n.freecpu_permission = freecpu_permission;
    n.owner = owner;
    n.require_recipients = require_recipients;
  });

}

ACTION cpuservice::payerupdate( name cpu_payer, name new_owner,  name new_freecpu_permission, vector<name>new_require_recipients){
  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto itr = _cpupayers.find(cpu_payer.value);
  check(itr != _cpupayers.end(), "cpu_payer not registered.");
  require_auth(itr->owner);
  //validate inputs
  check(is_account(new_owner), "new_owner isn't a valid account.");
  
  std::set<name> dup_recipients;
  for(name recipient : new_require_recipients){
    check(is_account(recipient), recipient.to_string()+" isn't a valid account.");
    check(dup_recipients.insert(recipient).second, "Duplicate recipient "+recipient.to_string() );
  }
}

ACTION cpuservice::payerdel( name cpu_payer ){
  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto itr = _cpupayers.find(cpu_payer.value);
  check(itr != _cpupayers.end(), "cpu_payer not registered.");
  require_auth(itr->owner);

  whitelist_table _whitelist(get_self(), cpu_payer.value);
  check(_whitelist.end() == _whitelist.begin(), "can't delete cpu_payer when it's whitelist is populated. delete whitelist entries first." );

  _cpupayers.erase(itr);
}

ACTION cpuservice::whitelistadd( name cpu_payer, name contract, name action){
  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto p = _cpupayers.get(cpu_payer.value);
  require_auth(p.owner);

  whitelist_table _whitelist(get_self(), cpu_payer.value); //each registered cpu_payer has it's own whitelist
  auto by_cont_act = _whitelist.get_index<"bycontact"_n>();

  
  uint128_t exact_match = (uint128_t{contract.value} << 64) | action.value;

  auto itr = _whitelist.find(exact_match);
  if(itr != _whitelist.end() ){//existing entry
    check(false, contract.to_string()+"::"+action.to_string()+" is already on the whitelist");
  }
  else{//doesn't exist in table

    //check if contract already has a wildcard
    uint128_t wildcard = (uint128_t{contract.value} << 64) | name(0).value;
    check(_whitelist.find(wildcard) == _whitelist.end(), "can't whitelist individual actions when the contract has a wildcard. Remove whitelisted actions before applying a wildcard.");

    _whitelist.emplace(p.owner, [&](auto& n) {
      n.id = _whitelist.available_primary_key();
      n.contract = contract;
      n.action = action;
    });
  
  }

}

ACTION cpuservice::whitelistdel( name cpu_payer, uint64_t id){
  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto p = _cpupayers.get(cpu_payer.value);
  require_auth(p.owner);

  whitelist_table _whitelist(get_self(), cpu_payer.value);
  auto itr = _whitelist.find(id);
  check(itr != _whitelist.end(), "id not found in whitelist" );
  _whitelist.erase(itr);

}

ACTION cpuservice::freecpu(name user, name cpu_payer){
  check(get_sender().value == 0, "freecpu can't be called inline");
  cpupayers_table _cpupayers(get_self(), get_self().value);
  auto p = _cpupayers.get(cpu_payer.value);
  //require the permission_level of the cpu payer account. this must be the first authorizer.
  require_auth(permission_level(p.cpu_payer, p.freecpu_permission) ); //via a shared private key with linkauth on this action.

  //require_auth(user); //optional second authorizer=user to keep stats per user

  //notify required recipients
  if(!p.require_recipients.empty() ){
    for(name recipient : p.require_recipients){
      require_recipient(recipient);
    }
  }

  size_t size = transaction_size();
  char buf[size];
  size_t read = read_transaction( buf, size );
  check( size == read, "read_transaction failed");
  eosio::transaction t = unpack<eosio::transaction>( buf, size );

  
  check(t.actions[0].name == name("freecpu") && t.actions[0].account == get_self(), "Free cpu action should be first" );
  check(t.actions.size() != 1, "Freecpu must be called in combination with whitelisted actions" );


  whitelist_table _whitelist(get_self(), cpu_payer.value); //each registered cpu_payer has it's own whitelist
  auto by_cont_act = _whitelist.get_index<"bycontact"_n>();
  //skip first action freecpu
  for(std::vector<int>::size_type i = 1; i != t.actions.size(); ++i) {

      uint128_t exact_match = (uint128_t{t.actions[i].account.value} << 64) | t.actions[i].name.value;
      if(by_cont_act.find(exact_match) != by_cont_act.end() ){
        //allowed: exact match
      }
      else{
        uint128_t wildcard = (uint128_t{t.actions[i].account.value} << 64) | 0;
        if(by_cont_act.find(wildcard) != by_cont_act.end() ){
          //allowed: contract is wildcarded
        }
        else{
          check(false, "Freecpu must be called in combination with whitelisted actions");
        }
      }
  }
   

}




