// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <amount.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <node/coinstats.h>
#include <node/context.h>
#include <node/utxo_snapshot.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/ref.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <stdint.h>

#include <univalue.h>

#include <condition_variable>
#include <key_io.h>
#include <memory>
#include <mutex>

static bool GetBlockChecked(CBlock& block, const CBlockIndex* pblockindex)
{
    if (IsBlockPruned(pblockindex)) {
        return false;
    }

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        // Block not found on disk. This could be because we have the block
        // header in our index but not yet have the block or did not accept the
        // block.
        return false;
    }

    return true;
}

void ScriptPubKeyToAddress(const CScript& scriptPubKey, UniValue& out)
{
    TxoutType type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired) || type == TxoutType::PUBKEY) {
        return;
    }

    for (const CTxDestination& addr : addresses) {
        out.push_back(EncodeDestination(addr));
    }
}

UniValue builAddressBallance(std::string address)
{
    if (address == "")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Address is empty.");

    CBlock block;
    const CBlockIndex* pblockindex;

    CAmount balance = 0;
    CAmount pend_balance = 0;
    CAmount imature_balance = 0;

    BlockMap& map = g_chainman.BlockIndex();
    // printf("Chain Manager Total Blocks: %d\n", map.size());
    BlockMap::iterator it = map.begin();
    while (it != map.end()) {
        pblockindex = it->second;
        if (!pblockindex) {
            // throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            continue;
        }

        if (!GetBlockChecked(block, pblockindex)) {
            // throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            continue;
        }

        for (auto tx = block.vtx.begin(); tx != block.vtx.end(); tx++) {
            for (const CTxOutput& output : tx.base()->get()->GetOutputs()) {
                const CTxOut& txout = output.GetTxOut();
                UniValue o(UniValue::VARR);
                ScriptPubKeyToAddress(txout.scriptPubKey, o);

                for (size_t k = 0; k < o.size(); k++) {
                    if (o[k].get_str() == address) {
                        if (output.IsMWEB()) {
                            // out.pushKV("output_id", output.ToMWEB().ToHex());
                        } else {
                            balance += txout.nValue;
                        }
                    }
                }
            }
        }
        it++;
    }
    UniValue result(UniValue::VOBJ);

    result.pushKV("balance", ValueFromAmount(balance));
    result.pushKV("pend_balance", ValueFromAmount(pend_balance));
    result.pushKV("imature_balance", ValueFromAmount(imature_balance));

    return result;
}

static RPCHelpMan getBallanceForAddress()
{
    return RPCHelpMan{
        "getBallanceForAddress",
        "",
        {
            {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
        },
        RPCResult{
            RPCResult::Type::NUM, "", "balance of the address"},
        RPCExamples{
            HelpExampleCli("getBallanceForAddress", "GXfuiMpNtQteiiythiUSKWrmDjLo9kjJPY") + HelpExampleRpc("getBallanceForAddress", "GUBz9BJ35sssPfW6kHbpkZfjNoQAg5tgbN")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string address = request.params[0].get_str();

            return builAddressBallance(address);
        },
    };
}


void RegisterAddressRPCCommands(CRPCTable& t)
{
    // clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "address",         "getBallanceForAddress",  &getBallanceForAddress,  {"address"} },
};

    // clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
