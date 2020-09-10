#include <eosio/eosio.hpp>
#include <eosio/transaction.hpp>
#include <eosio/singleton.hpp>

using namespace std;
using namespace eosio;

CONTRACT cpuservice : public contract {
  public:
    using contract::contract;
    
    ACTION freecpu(name user, name cpu_payer);
    ACTION whitelistadd( name cpu_payer, name contract, name action);
    ACTION whitelistdel( name cpu_payer, uint64_t id);


    ACTION payerreg( name owner, name cpu_payer, name freecpu_permission, vector<name>require_recipients);
    ACTION payerupdate( name cpu_payer, name new_owner, name new_freecpu_permission, vector<name>new_require_recipients);
    ACTION payerdel( name cpu_payer );


  private:


    TABLE cpupayers {
        name cpu_payer;
        name freecpu_permission;
        name owner;
        vector<name> require_recipients;
        bool r1 = false;
        uint64_t r2;

        auto primary_key() const { return cpu_payer.value; }
    };
    typedef multi_index<name("cpupayers"), cpupayers> cpupayers_table;

    //scoped by cpu_payer
    TABLE whitelist {
      uint64_t id;
      name    contract;
      name  action;

      auto primary_key() const { return id; }
      uint128_t by_cont_act() const { return (uint128_t{contract.value} << 64) | action.value; }
    };
    typedef multi_index<name("whitelist"), whitelist,
      eosio::indexed_by<"bycontact"_n, eosio::const_mem_fun<whitelist, uint128_t, &whitelist::by_cont_act>>
    > whitelist_table;

};
