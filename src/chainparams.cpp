// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <hash.h> // for signet block challenge hash
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>
#include <key_io.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>


#include "arith_uint256.h"

#define GENESIS_FINDER
 
#define GENESIS_BITS 0x1e0ffff0
//#define GENESIS_BITS 0x1d00ffff
//#define GENESIS_BITS 0x429aff

#define GENESIS_VERSION 1

#define MAIN_GENESIS_TIME_STAMP "2/Dec/2024 - No pain no gain"

#define MAIN_GENESIS_TIME 1737931953
#define MAIN_GENESIS_NONCE 697246
#define MAIN_GENESIS_HASH "0x0deebd822b221a7beec055b80cecb949256f50b21bf8c6f899da1b7eef876061"
#define MAIN_GENESIS_MERKLE_ROOT "0x0e2d71deb3c222550215e240c5b93b5438c3327f6a4904123e51c346dcb4b324"

#define TEST_GENESIS_TIME_STAMP "2/Dec/2024 - No pain no gain"
#define TEST_GENESIS_TIME 1737931953
#define TEST_GENESIS_NONCE 697246
#define TEST_GENESIS_HASH "0x0deebd822b221a7beec055b80cecb949256f50b21bf8c6f899da1b7eef876061"
#define TEST_GENESIS_MERKLE_ROOT "0x0e2d71deb3c222550215e240c5b93b5438c3327f6a4904123e51c346dcb4b324"


#if defined(GENESIS_FINDER)
// Erases `count` lines, including the current line
void eraseLines(int count) {
    if (count > 0) {
        std::cout << "\x1b[2K"; // Delete current line
        // i=1 because we included the first line
        for (int i = 1; i < count; i++) {
            std::cout
            << "\x1b[1A" // Move cursor up one
            << "\x1b[2K"; // Delete the entire line
        }
        std::cout << "\r"; // Resume the cursor at beginning of line
    }
}

static void FindMainNetGenesisBlock(CBlock& block)
{
    block.nTime = std::time(0); // current time

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    printf("Finding the genesis block\n");
    printf("\n");

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetPoWHash(); 
        if (nNonce % 1000 == 0) {
            eraseLines(1);
            std::cout << "Nonce: " << nNonce << " Pow 0x" << hash.GetHex().c_str() << std::flush;
        }
        if (UintToArith256(hash) <= bnTarget) {
            block.hashMerkleRoot = BlockMerkleRoot(block);

            printf("\n\n");  
            printf("*********************** GENESIS BLOCK FOUND ***********************\n");
            printf("Genesis is %s\n\n", block.ToString().c_str());
            printf("   Pow: 0x%s\n", hash.GetHex().c_str());
            printf("  Time: %d\n", block.nTime);
            printf(" Nonce: %d\n", nNonce);
            printf("  Bits: 0x%x\n", block.nBits);
            printf("  Hash: 0x%s\n", block.GetHash().GetHex().c_str());
            printf("Merkle: 0x%s\n", block.hashMerkleRoot.GetHex().c_str());
            printf("*******************************************************************\n\n");
            assert(false);
        }
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("NetGenesisBlock: could not find genesis block");
    assert(false);
}
#endif



/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, const char* pszTimestamp)
{
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = COIN_SUBSIDY;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = GENESIS_BITS;
    genesis.nNonce   = nNonce;
    genesis.nVersion = GENESIS_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


int32_t percent(int32_t X, int32_t N){
    return ((X / 100) * N);
}

int32_t minutes(int32_t X){
    return X * 60;
}

int32_t hours(int32_t X){
    return X * 60 * 60;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 100000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 504365055 0x1e0fffff
        consensus.nPowTargetTimespan = hours(6);
        consensus.nPowTargetSpacing = minutes(1); 
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nMinerConfirmationWindow = consensus.nPowTargetTimespan / consensus.nPowTargetSpacing * 4;
        consensus.nRuleChangeActivationThreshold = percent(95, consensus.nMinerConfirmationWindow );

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 0; // End November 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 2370816; // 364 days later

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 0; // End Feb 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 2427264; // 364 days later

        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.defaultAssumeValid = uint256S("0x0");
        
        printf("powLimit: %u\n", UintToArith256(consensus.powLimit).GetCompact());
        printf("powLimit: %x\n", UintToArith256(consensus.powLimit).GetCompact());

        arith_uint256 bnTarget;
        bnTarget.SetCompact(4365055);

        printf("powLimit: 0x%s\n", bnTarget.GetHex().c_str());


        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xae;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xd1;
  
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(MAIN_GENESIS_TIME, MAIN_GENESIS_NONCE, MAIN_GENESIS_TIME_STAMP);
        consensus.hashGenesisBlock = genesis.GetHash();

        printf("GetPoWHash: 0x%s\n", genesis.GetPoWHash().GetHex().c_str());

        if( consensus.hashGenesisBlock != uint256S(MAIN_GENESIS_HASH) || 
            genesis.hashMerkleRoot != uint256S(MAIN_GENESIS_MERKLE_ROOT) ||
            gArgs.GetBoolArg("-genesis", false))
        {
            if(consensus.hashGenesisBlock != uint256S(MAIN_GENESIS_HASH))
            {
                printf("Invalid Hash \n");
            }
            if(genesis.hashMerkleRoot != uint256S(MAIN_GENESIS_MERKLE_ROOT))
            {
                printf("Invalid hMerkleRoot \n");
            }

            if(!gArgs.GetBoolArg("-genesis", false))
		    {
                printf("### Invalid Genesis Block found ### \n");
		        printf("Generating it \n\n");
            }

            FindMainNetGenesisBlock(genesis);
        }


        #if defined(DEBUG_GENESIS)
            std::cout << std::endl;	
            std::cout << "---------------------------------------------------------------------------------------------------" << std::endl;	
            std::cout << "CMainParams" << std::endl;
            printf("    Time = %u \n", genesis.nTime);
            printf("    Nonce = %u \n", genesis.nNonce);
            printf("    Bits: 0x%08x\n", genesis.nBits);
            printf("    Hash = 0x%s\n", genesis.GetHash().ToString().c_str());
            printf("    Merkle Root = 0x%s\n", genesis.hashMerkleRoot.ToString().c_str());
            //printf("Main Genesis hashStateRoot = %sn", genesis.hashStateRoot.ToString().c_str());	
            std::cout << "---------------------------------------------------------------------------------------------------" << std::endl;	
            std::cout << std::endl;	
        #endif

        assert(consensus.hashGenesisBlock == uint256S(MAIN_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(MAIN_GENESIS_MERKLE_ROOT));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.clear();
        vSeeds.emplace_back("dnsseed.rcn-project.com");
        /*vSeeds.emplace_back("localhost:9101");
        vSeeds.emplace_back("localhost:9102");
        vSeeds.emplace_back("localhost:9103");*/

        base58Prefixes[PUBKEY_ADDRESS]  = std::vector<unsigned char>(1,60); // R
        base58Prefixes[SCRIPT_ADDRESS]  = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY]      = std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "ltc";
        mweb_hrp = "ltcmweb";

        vFixedSeeds.clear();// = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {  0, uint256S("0x0")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 17280 fdb81fc2edae4e315716890bd343d814184ea50331cd47166e19120a5163a678
            /* nTime    */ MAIN_GENESIS_TIME,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.0
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 2225664; // March 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 2435328; // 364 days later

        // Deployment of MWEB (LIP-0002, LIP-0003, and LIP-0004)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartHeight = 2209536; // Jan/Feb 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeoutHeight = 2419200; // 364 days later

        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000004260a1758f04aa");
        consensus.defaultAssumeValid = uint256S("0x4a280c0e150e3b74ebe19618e6394548c8a39d5549fd9941b9c431c73822fbd5"); // 1737876

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 19335;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(TEST_GENESIS_TIME, TEST_GENESIS_NONCE, TEST_GENESIS_TIME_STAMP);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S(TEST_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(TEST_GENESIS_MERKLE_ROOT));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.litecointools.com");
        vSeeds.emplace_back("seed-b.litecoin.loshan.co.uk");
        vSeeds.emplace_back("dnsseed-testnet.thrasher.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tltc";
        mweb_hrp = "tmweb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {300, uint256S("54e6075affe658d6574e04c9245a7920ad94dc5af8f5b37fd9a094e317769740")},
                {2056, uint256S("17748a31ba97afdc9a4f86837a39d287e3e7c7290a08a1d816c5969c78a83289")},
                {2352616, uint256S("7540437e7bf7831fa872ba8cfae85951a1e5dbb04c201b6f5def934d9299f3c2")}
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 36d8ad003bac090cf7bf4e24fbe1d319554c8933b9314188d6096ac12648764d
            /* nTime    */ 1607986972,
            /* nTxCount */ 4229067,
            /* dTxRate  */ 0.06527021772939347,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of MWEB (LIP-0002 and LIP-0003)
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nStartTime = 1601450001; // September 30, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_MWEB].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(TEST_GENESIS_TIME, TEST_GENESIS_NONCE, TEST_GENESIS_TIME_STAMP);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S(TEST_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(TEST_GENESIS_MERKLE_ROOT));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rltc";
        mweb_hrp = "tmweb";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nStartHeight, int64_t nTimeoutHeight)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].nStartHeight = nStartHeight;
        consensus.vDeployments[d].nTimeoutHeight = nTimeoutHeight;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() < 3 || 5 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:heightstart:heightend]");
        }
        int64_t nStartTime, nTimeout, nStartHeight, nTimeoutHeight;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() > 3 && !ParseInt64(vDeploymentParams[3], &nStartHeight)) {
            throw std::runtime_error(strprintf("Invalid nStartHeight (%s)", vDeploymentParams[3]));
        }
        if (vDeploymentParams.size() > 4 && !ParseInt64(vDeploymentParams[4], &nTimeoutHeight)) {
            throw std::runtime_error(strprintf("Invalid nTimeoutHeight (%s)", vDeploymentParams[4]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, start_height=%d, timeout_height=%d\n", vDeploymentParams[0], nStartTime, nTimeout, nStartHeight, nTimeoutHeight);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams()); // TODO: Support SigNet
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
