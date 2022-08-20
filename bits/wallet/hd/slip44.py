# reference: slip-44
# https://github.com/satoshilabs/slips/blob/master/slip-0044.md

## the following is a port of bitcoinjs/bip44-constants
## https://github.com/bitcoinjs/bip44-constants/blob/v149.0.0/index.js
# Format for each row:
# [ constant, coinSymbol, coinName ]
SLIP44_CONSTANTS = [
    [0x80000000, "BTC", "Bitcoin"],
    [0x80000001, "", "Testnet (all coins)"],
    [0x80000002, "LTC", "Litecoin"],
    [0x80000003, "DOGE", "Dogecoin"],
    [0x80000004, "RDD", "Reddcoin"],
    [0x80000005, "DASH", "Dash (ex Darkcoin)"],
    [0x80000006, "PPC", "Peercoin"],
    [0x80000007, "NMC", "Namecoin"],
    [0x80000008, "FTC", "Feathercoin"],
    [0x80000009, "XCP", "Counterparty"],
    [0x8000000A, "BLK", "Blackcoin"],
    [0x8000000B, "NSR", "NuShares"],
    [0x8000000C, "NBT", "NuBits"],
    [0x8000000D, "MZC", "Mazacoin"],
    [0x8000000E, "VIA", "Viacoin"],
    [0x8000000F, "XCH", "ClearingHouse"],
    [0x80000010, "RBY", "Rubycoin"],
    [0x80000011, "GRS", "Groestlcoin"],
    [0x80000012, "DGC", "Digitalcoin"],
    [0x80000013, "CCN", "Cannacoin"],
    [0x80000014, "DGB", "DigiByte"],
    [0x80000015, "", "Open Assets"],
    [0x80000016, "MONA", "Monacoin"],
    [0x80000017, "CLAM", "Clams"],
    [0x80000018, "XPM", "Primecoin"],
    [0x80000019, "NEOS", "Neoscoin"],
    [0x8000001A, "JBS", "Jumbucks"],
    [0x8000001B, "ZRC", "ziftrCOIN"],
    [0x8000001C, "VTC", "Vertcoin"],
    [0x8000001D, "NXT", "NXT"],
    [0x8000001E, "BURST", "Burst"],
    [0x8000001F, "MUE", "MonetaryUnit"],
    [0x80000020, "ZOOM", "Zoom"],
    [0x80000021, "VASH", "Virtual Cash also known as VPNcoin"],
    [0x80000022, "CDN", "Canada eCoin"],
    [0x80000023, "SDC", "ShadowCash"],
    [0x80000024, "PKB", "ParkByte"],
    [0x80000025, "PND", "Pandacoin"],
    [0x80000026, "START", "StartCOIN"],
    [0x80000027, "MOIN", "MOIN"],
    [0x80000028, "EXP", "Expanse"],
    [0x80000029, "EMC2", "Einsteinium"],
    [0x8000002A, "DCR", "Decred"],
    [0x8000002B, "XEM", "NEM"],
    [0x8000002C, "PART", "Particl"],
    [0x8000002D, "ARG", "Argentum (dead)"],
    [0x8000002E, "", "Libertas"],
    [0x8000002F, "", "Posw coin"],
    [0x80000030, "SHR", "Shreeji"],
    [0x80000031, "GCR", "Global Currency Reserve (GCRcoin)"],
    [0x80000032, "NVC", "Novacoin"],
    [0x80000033, "AC", "Asiacoin"],
    [0x80000034, "BTCD", "BitcoinDark"],
    [0x80000035, "DOPE", "Dopecoin"],
    [0x80000036, "TPC", "Templecoin"],
    [0x80000037, "AIB", "AIB"],
    [0x80000038, "EDRC", "EDRCoin"],
    [0x80000039, "SYS", "Syscoin"],
    [0x8000003A, "SLR", "Solarcoin"],
    [0x8000003B, "SMLY", "Smileycoin"],
    [0x8000003C, "ETH", "Ether"],
    [0x8000003D, "ETC", "Ether Classic"],
    [0x8000003E, "PSB", "Pesobit"],
    [0x8000003F, "LDCN", "Landcoin (dead)"],
    [0x80000040, "", "Open Chain"],
    [0x80000041, "XBC", "Bitcoinplus"],
    [0x80000042, "IOP", "Internet of People"],
    [0x80000043, "NXS", "Nexus"],
    [0x80000044, "INSN", "InsaneCoin"],
    [0x80000045, "OK", "OKCash"],
    [0x80000046, "BRIT", "BritCoin"],
    [0x80000047, "CMP", "Compcoin"],
    [0x80000048, "CRW", "Crown"],
    [0x80000049, "BELA", "BelaCoin"],
    [0x8000004A, "ICX", "ICON"],
    [0x8000004B, "FJC", "FujiCoin"],
    [0x8000004C, "MIX", "MIX"],
    [0x8000004D, "XVG", "Verge Currency"],
    [0x8000004E, "EFL", "Electronic Gulden"],
    [0x8000004F, "CLUB", "ClubCoin"],
    [0x80000050, "RICHX", "RichCoin"],
    [0x80000051, "POT", "Potcoin"],
    [0x80000052, "QRK", "Quarkcoin"],
    [0x80000053, "TRC", "Terracoin"],
    [0x80000054, "GRC", "Gridcoin"],
    [0x80000055, "AUR", "Auroracoin"],
    [0x80000056, "IXC", "IXCoin"],
    [0x80000057, "NLG", "Gulden"],
    [0x80000058, "BITB", "BitBean"],
    [0x80000059, "BTA", "Bata"],
    [0x8000005A, "XMY", "Myriadcoin"],
    [0x8000005B, "BSD", "BitSend"],
    [0x8000005C, "UNO", "Unobtanium"],
    [0x8000005D, "MTR", "MasterTrader"],
    [0x8000005E, "GB", "GoldBlocks"],
    [0x8000005F, "SHM", "Saham"],
    [0x80000060, "CRX", "Chronos"],
    [0x80000061, "BIQ", "Ubiquoin"],
    [0x80000062, "EVO", "Evotion"],
    [0x80000063, "STO", "SaveTheOcean"],
    [0x80000064, "BIGUP", "BigUp"],
    [0x80000065, "GAME", "GameCredits"],
    [0x80000066, "DLC", "Dollarcoins"],
    [0x80000067, "ZYD", "Zayedcoin"],
    [0x80000068, "DBIC", "Dubaicoin"],
    [0x80000069, "STRAT", "Stratis"],
    [0x8000006A, "SH", "Shilling"],
    [0x8000006B, "MARS", "MarsCoin"],
    [0x8000006C, "UBQ", "Ubiq"],
    [0x8000006D, "PTC", "Pesetacoin"],
    [0x8000006E, "NRO", "Neurocoin"],
    [0x8000006F, "ARK", "ARK"],
    [0x80000070, "USC", "UltimateSecureCashMain"],
    [0x80000071, "THC", "Hempcoin"],
    [0x80000072, "LINX", "Linx"],
    [0x80000073, "ECN", "Ecoin"],
    [0x80000074, "DNR", "Denarius"],
    [0x80000075, "PINK", "Pinkcoin"],
    [0x80000076, "ATOM", "Atom"],
    [0x80000077, "PIVX", "Pivx"],
    [0x80000078, "FLASH", "Flashcoin"],
    [0x80000079, "ZEN", "Zencash"],
    [0x8000007A, "PUT", "Putincoin"],
    [0x8000007B, "ZNY", "BitZeny"],
    [0x8000007C, "UNIFY", "Unify"],
    [0x8000007D, "XST", "StealthCoin"],
    [0x8000007E, "BRK", "Breakout Coin"],
    [0x8000007F, "VC", "Vcash"],
    [0x80000080, "XMR", "Monero"],
    [0x80000081, "VOX", "Voxels"],
    [0x80000082, "NAV", "NavCoin"],
    [0x80000083, "FCT", "Factom Factoids"],
    [0x80000084, "EC", "Factom Entry Credits"],
    [0x80000085, "ZEC", "Zcash"],
    [0x80000086, "LSK", "Lisk"],
    [0x80000087, "STEEM", "Steem"],
    [0x80000088, "XZC", "ZCoin"],
    [0x80000089, "RBTC", "RSK"],
    [0x8000008A, "", "Giftblock"],
    [0x8000008B, "RPT", "RealPointCoin"],
    [0x8000008C, "LBC", "LBRY Credits"],
    [0x8000008D, "KMD", "Komodo"],
    [0x8000008E, "BSQ", "bisq Token"],
    [0x8000008F, "RIC", "Riecoin"],
    [0x80000090, "XRP", "Ripple"],
    [0x80000091, "BCH", "Bitcoin Cash"],
    [0x80000092, "NEBL", "Neblio"],
    [0x80000093, "ZCL", "ZClassic"],
    [0x80000094, "XLM", "Stellar Lumens"],
    [0x80000095, "NLC2", "NoLimitCoin2"],
    [0x80000096, "WHL", "WhaleCoin"],
    [0x80000097, "ERC", "EuropeCoin"],
    [0x80000098, "DMD", "Diamond"],
    [0x80000099, "BTM", "Bytom"],
    [0x8000009A, "BIO", "Biocoin"],
    [0x8000009B, "XWCC", "Whitecoin Classic"],
    [0x8000009C, "BTG", "Bitcoin Gold"],
    [0x8000009D, "BTC2X", "Bitcoin 2x"],
    [0x8000009E, "SSN", "SuperSkynet"],
    [0x8000009F, "TOA", "TOACoin"],
    [0x800000A0, "BTX", "Bitcore"],
    [0x800000A1, "ACC", "Adcoin"],
    [0x800000A2, "BCO", "Bridgecoin"],
    [0x800000A3, "ELLA", "Ellaism"],
    [0x800000A4, "PIRL", "Pirl"],
    [0x800000A5, "XNO", "Nano"],
    [0x800000A6, "VIVO", "Vivo"],
    [0x800000A7, "FRST", "Firstcoin"],
    [0x800000A8, "HNC", "Helleniccoin"],
    [0x800000A9, "BUZZ", "BUZZ"],
    [0x800000AA, "MBRS", "Ember"],
    [0x800000AB, "HC", "Hcash"],
    [0x800000AC, "HTML", "HTMLCOIN"],
    [0x800000AD, "ODN", "Obsidian"],
    [0x800000AE, "ONX", "OnixCoin"],
    [0x800000AF, "RVN", "Ravencoin"],
    [0x800000B0, "GBX", "GoByte"],
    [0x800000B1, "BTCZ", "BitcoinZ"],
    [0x800000B2, "POA", "Poa"],
    [0x800000B3, "NYC", "NewYorkCoin"],
    [0x800000B4, "MXT", "MarteXcoin"],
    [0x800000B5, "WC", "Wincoin"],
    [0x800000B6, "MNX", "Minexcoin"],
    [0x800000B7, "BTCP", "Bitcoin Private"],
    [0x800000B8, "MUSIC", "Musicoin"],
    [0x800000B9, "BCA", "Bitcoin Atom"],
    [0x800000BA, "CRAVE", "Crave"],
    [0x800000BB, "STAK", "STRAKS"],
    [0x800000BC, "WBTC", "World Bitcoin"],
    [0x800000BD, "LCH", "LiteCash"],
    [0x800000BE, "EXCL", "ExclusiveCoin"],
    [0x800000BF, "", "Lynx"],
    [0x800000C0, "LCC", "LitecoinCash"],
    [0x800000C1, "XFE", "Feirm"],
    [0x800000C2, "EOS", "EOS"],
    [0x800000C3, "TRX", "Tron"],
    [0x800000C4, "KOBO", "Kobocoin"],
    [0x800000C5, "HUSH", "HUSH"],
    [0x800000C6, "BANANO", "Bananos"],
    [0x800000C7, "ETF", "ETF"],
    [0x800000C8, "OMNI", "Omni"],
    [0x800000C9, "BIFI", "BitcoinFile"],
    [0x800000CA, "UFO", "Uniform Fiscal Object"],
    [0x800000CB, "CNMC", "Cryptonodes"],
    [0x800000CC, "BCN", "Bytecoin"],
    [0x800000CD, "RIN", "Ringo"],
    [0x800000CE, "ATP", "Alaya"],
    [0x800000CF, "EVT", "everiToken"],
    [0x800000D0, "ATN", "ATN"],
    [0x800000D1, "BIS", "Bismuth"],
    [0x800000D2, "NEET", "NEETCOIN"],
    [0x800000D3, "BOPO", "BopoChain"],
    [0x800000D4, "OOT", "Utrum"],
    [0x800000D5, "ALIAS", "Alias"],
    [0x800000D6, "MONK", "Monkey Project"],
    [0x800000D7, "BOXY", "BoxyCoin"],
    [0x800000D8, "FLO", "Flo"],
    [0x800000D9, "MEC", "Megacoin"],
    [0x800000DA, "BTDX", "BitCloud"],
    [0x800000DB, "XAX", "Artax"],
    [0x800000DC, "ANON", "ANON"],
    [0x800000DD, "LTZ", "LitecoinZ"],
    [0x800000DE, "BITG", "Bitcoin Green"],
    [0x800000DF, "ICP", "Internet Computer (DFINITY)"],
    [0x800000E0, "SMART", "Smartcash"],
    [0x800000E1, "XUEZ", "XUEZ"],
    [0x800000E2, "HLM", "Helium"],
    [0x800000E3, "WEB", "Webchain"],
    [0x800000E4, "ACM", "Actinium"],
    [0x800000E5, "NOS", "NOS Stable Coins"],
    [0x800000E6, "BITC", "BitCash"],
    [0x800000E7, "HTH", "Help The Homeless Coin"],
    [0x800000E8, "TZC", "Trezarcoin"],
    [0x800000E9, "VAR", "Varda"],
    [0x800000EA, "IOV", "IOV"],
    [0x800000EB, "FIO", "FIO"],
    [0x800000EC, "BSV", "BitcoinSV"],
    [0x800000ED, "DXN", "DEXON"],
    [0x800000EE, "QRL", "Quantum Resistant Ledger"],
    [0x800000EF, "PCX", "ChainX"],
    [0x800000F0, "LOKI", "Loki"],
    [0x800000F1, "", "Imagewallet"],
    [0x800000F2, "NIM", "Nimiq"],
    [0x800000F3, "SOV", "Sovereign Coin"],
    [0x800000F4, "JCT", "Jibital Coin"],
    [0x800000F5, "SLP", "Simple Ledger Protocol"],
    [0x800000F6, "EWT", "Energy Web"],
    [0x800000F7, "UC", "Ulord"],
    [0x800000F8, "EXOS", "EXOS"],
    [0x800000F9, "ECA", "Electra"],
    [0x800000FA, "SOOM", "Soom"],
    [0x800000FB, "XRD", "Redstone"],
    [0x800000FC, "FREE", "FreeCoin"],
    [0x800000FD, "NPW", "NewPowerCoin"],
    [0x800000FE, "BST", "BlockStamp"],
    [0x800000FF, "", "SmartHoldem"],
    [0x80000100, "NANO", "Bitcoin Nano"],
    [0x80000101, "BTCC", "Bitcoin Core"],
    [0x80000102, "", "Zen Protocol"],
    [0x80000103, "ZEST", "Zest"],
    [0x80000104, "ABT", "ArcBlock"],
    [0x80000105, "PION", "Pion"],
    [0x80000106, "DT3", "DreamTeam3"],
    [0x80000107, "ZBUX", "Zbux"],
    [0x80000108, "KPL", "Kepler"],
    [0x80000109, "TPAY", "TokenPay"],
    [0x8000010A, "ZILLA", "ChainZilla"],
    [0x8000010B, "ANK", "Anker"],
    [0x8000010C, "BCC", "BCChain"],
    [0x8000010D, "HPB", "HPB"],
    [0x8000010E, "ONE", "ONE"],
    [0x8000010F, "SBC", "SBC"],
    [0x80000110, "IPC", "IPChain"],
    [0x80000111, "DMTC", "Dominantchain"],
    [0x80000112, "OGC", "Onegram"],
    [0x80000113, "SHIT", "Shitcoin"],
    [0x80000114, "ANDES", "Andescoin"],
    [0x80000115, "AREPA", "Arepacoin"],
    [0x80000116, "BOLI", "Bolivarcoin"],
    [0x80000117, "RIL", "Rilcoin"],
    [0x80000118, "HTR", "Hathor Network"],
    [0x80000119, "FCTID", "Factom ID"],
    [0x8000011A, "BRAVO", "BRAVO"],
    [0x8000011B, "ALGO", "Algorand"],
    [0x8000011C, "BZX", "Bitcoinzero"],
    [0x8000011D, "GXX", "GravityCoin"],
    [0x8000011E, "HEAT", "HEAT"],
    [0x8000011F, "XDN", "DigitalNote"],
    [0x80000120, "FSN", "FUSION"],
    [0x80000121, "CPC", "Capricoin"],
    [0x80000122, "BOLD", "Bold"],
    [0x80000123, "IOST", "IOST"],
    [0x80000124, "TKEY", "Tkeycoin"],
    [0x80000125, "USE", "Usechain"],
    [0x80000126, "BCZ", "BitcoinCZ"],
    [0x80000127, "IOC", "Iocoin"],
    [0x80000128, "ASF", "Asofe"],
    [0x80000129, "MASS", "MASS"],
    [0x8000012A, "FAIR", "FairCoin"],
    [0x8000012B, "NUKO", "Nekonium"],
    [0x8000012C, "GNX", "Genaro Network"],
    [0x8000012D, "DIVI", "Divi Project"],
    [0x8000012E, "CMT", "Community"],
    [0x8000012F, "EUNO", "EUNO"],
    [0x80000130, "IOTX", "IoTeX"],
    [0x80000131, "ONION", "DeepOnion"],
    [0x80000132, "8BIT", "8Bit"],
    [0x80000133, "ATC", "AToken Coin"],
    [0x80000134, "BTS", "Bitshares"],
    [0x80000135, "CKB", "Nervos CKB"],
    [0x80000136, "UGAS", "Ultrain"],
    [0x80000137, "ADS", "Adshares"],
    [0x80000138, "ARA", "Aura"],
    [0x80000139, "ZIL", "Zilliqa"],
    [0x8000013A, "MOAC", "MOAC"],
    [0x8000013B, "SWTC", "SWTC"],
    [0x8000013C, "VNSC", "vnscoin"],
    [0x8000013D, "PLUG", "Pl^g"],
    [0x8000013E, "MAN", "Matrix AI Network"],
    [0x8000013F, "ECC", "ECCoin"],
    [0x80000140, "RPD", "Rapids"],
    [0x80000141, "RAP", "Rapture"],
    [0x80000142, "GARD", "Hashgard"],
    [0x80000143, "ZER", "Zero"],
    [0x80000144, "EBST", "eBoost"],
    [0x80000145, "SHARD", "Shard"],
    [0x80000146, "MRX", "Metrix Coin"],
    [0x80000147, "CMM", "Commercium"],
    [0x80000148, "BLOCK", "Blocknet"],
    [0x80000149, "AUDAX", "AUDAX"],
    [0x8000014A, "LUNA", "Terra"],
    [0x8000014B, "ZPM", "zPrime"],
    [0x8000014C, "KUVA", "Kuva Utility Note"],
    [0x8000014D, "MEM", "MemCoin"],
    [0x8000014E, "CS", "Credits"],
    [0x8000014F, "SWIFT", "SwiftCash"],
    [0x80000150, "FIX", "FIX"],
    [0x80000151, "CPC", "CPChain"],
    [0x80000152, "VGO", "VirtualGoodsToken"],
    [0x80000153, "DVT", "DeVault"],
    [0x80000154, "N8V", "N8VCoin"],
    [0x80000155, "MTNS", "OmotenashiCoin"],
    [0x80000156, "BLAST", "BLAST"],
    [0x80000157, "DCT", "DECENT"],
    [0x80000158, "AUX", "Auxilium"],
    [0x80000159, "USDP", "USDP"],
    [0x8000015A, "HTDF", "HTDF"],
    [0x8000015B, "YEC", "Ycash"],
    [0x8000015C, "QLC", "QLC Chain"],
    [0x8000015D, "TEA", "Icetea Blockchain"],
    [0x8000015E, "ARW", "ArrowChain"],
    [0x8000015F, "MDM", "Medium"],
    [0x80000160, "CYB", "Cybex"],
    [0x80000161, "LTO", "LTO Network"],
    [0x80000162, "DOT", "Polkadot"],
    [0x80000163, "AEON", "Aeon"],
    [0x80000164, "RES", "Resistance"],
    [0x80000165, "AYA", "Aryacoin"],
    [0x80000166, "DAPS", "Dapscoin"],
    [0x80000167, "CSC", "CasinoCoin"],
    [0x80000168, "VSYS", "V Systems"],
    [0x80000169, "NOLLAR", "Nollar"],
    [0x8000016A, "XNOS", "NOS"],
    [0x8000016B, "CPU", "CPUchain"],
    [0x8000016C, "LAMB", "Lambda Storage Chain"],
    [0x8000016D, "VCT", "ValueCyber"],
    [0x8000016E, "CZR", "Canonchain"],
    [0x8000016F, "ABBC", "ABBC"],
    [0x80000170, "HET", "HET"],
    [0x80000171, "XAS", "Asch"],
    [0x80000172, "VDL", "Vidulum"],
    [0x80000173, "MED", "MediBloc"],
    [0x80000174, "ZVC", "ZVChain"],
    [0x80000175, "VESTX", "Vestx"],
    [0x80000176, "DBT", "DarkBit"],
    [0x80000177, "SEOS", "SuperEOS"],
    [0x80000178, "MXW", "Maxonrow"],
    [0x80000179, "ZNZ", "ZENZO"],
    [0x8000017A, "XCX", "XChain"],
    [0x8000017B, "SOX", "SonicX"],
    [0x8000017C, "NYZO", "Nyzo"],
    [0x8000017D, "ULC", "ULCoin"],
    [0x8000017E, "RYO", "Ryo Currency"],
    [0x8000017F, "KAL", "Kaleidochain"],
    [0x80000180, "XSN", "Stakenet"],
    [0x80000181, "DOGEC", "DogeCash"],
    [0x80000182, "BMV", "Bitcoin Matteo's Vision"],
    [0x80000183, "QBC", "Quebecoin"],
    [0x80000184, "IMG", "ImageCoin"],
    [0x80000185, "QOS", "QOS"],
    [0x80000186, "PKT", "PKT"],
    [0x80000187, "LHD", "LitecoinHD"],
    [0x80000188, "CENNZ", "CENNZnet"],
    [0x80000189, "HSN", "Hyper Speed Network"],
    [0x8000018A, "CRO", "Crypto.org Chain"],
    [0x8000018B, "UMBRU", "Umbru"],
    [0x8000018C, "EVER", "Everscale"],
    [0x8000018D, "NEAR", "NEAR Protocol"],
    [0x8000018E, "XPC", "XPChain"],
    [0x8000018F, "ZOC", "01coin"],
    [0x80000190, "NIX", "NIX"],
    [0x80000191, "UC", "Utopiacoin"],
    [0x80000192, "GALI", "Galilel"],
    [0x80000193, "OLT", "Oneledger"],
    [0x80000194, "XBI", "XBI"],
    [0x80000195, "DONU", "DONU"],
    [0x80000196, "EARTHS", "Earths"],
    [0x80000197, "HDD", "HDDCash"],
    [0x80000198, "SUGAR", "Sugarchain"],
    [0x80000199, "AILE", "AileCoin"],
    [0x8000019A, "TENT", "TENT"],
    [0x8000019B, "TAN", "Tangerine Network"],
    [0x8000019C, "AIN", "AIN"],
    [0x8000019D, "MSR", "Masari"],
    [0x8000019E, "SUMO", "Sumokoin"],
    [0x8000019F, "ETN", "Electroneum"],
    [0x800001A0, "BYTZ", "BYTZ"],
    [0x800001A1, "WOW", "Wownero"],
    [0x800001A2, "XTNC", "XtendCash"],
    [0x800001A3, "LTHN", "Lethean"],
    [0x800001A4, "NODE", "NodeHost"],
    [0x800001A5, "AGM", "Argoneum"],
    [0x800001A6, "CCX", "Conceal Network"],
    [0x800001A7, "TNET", "Title Network"],
    [0x800001A8, "TELOS", "TelosCoin"],
    [0x800001A9, "AION", "Aion"],
    [0x800001AA, "BC", "Bitcoin Confidential"],
    [0x800001AB, "KTV", "KmushiCoin"],
    [0x800001AC, "ZCR", "ZCore"],
    [0x800001AD, "ERG", "Ergo"],
    [0x800001AE, "PESO", "Criptopeso"],
    [0x800001AF, "BTC2", "Bitcoin 2"],
    [0x800001B0, "XRPHD", "XRPHD"],
    [0x800001B1, "WE", "WE Coin"],
    [0x800001B2, "KSM", "Kusama"],
    [0x800001B3, "PCN", "Peepcoin"],
    [0x800001B4, "NCH", "NetCloth"],
    [0x800001B5, "ICU", "CHIPO"],
    [0x800001B6, "LN", "LINK"],
    [0x800001B7, "DTP", "DeVault Token Protocol"],
    [0x800001B8, "BTCR", "Bitcoin Royale"],
    [0x800001B9, "AERGO", "AERGO"],
    [0x800001BA, "XTH", "Dothereum"],
    [0x800001BB, "LV", "Lava"],
    [0x800001BC, "PHR", "Phore"],
    [0x800001BD, "VITAE", "Vitae"],
    [0x800001BE, "COCOS", "Cocos-BCX"],
    [0x800001BF, "DIN", "Dinero"],
    [0x800001C0, "SPL", "Simplicity"],
    [0x800001C1, "YCE", "MYCE"],
    [0x800001C2, "XLR", "Solaris"],
    [0x800001C3, "KTS", "Klimatas"],
    [0x800001C4, "DGLD", "DGLD"],
    [0x800001C5, "XNS", "Insolar"],
    [0x800001C6, "EM", "EMPOW"],
    [0x800001C7, "SHN", "ShineBlocks"],
    [0x800001C8, "SEELE", "Seele"],
    [0x800001C9, "AE", "æternity"],
    [0x800001CA, "ODX", "ObsidianX"],
    [0x800001CB, "KAVA", "Kava"],
    [0x800001CC, "GLEEC", "GLEEC"],
    [0x800001CD, "FIL", "Filecoin"],
    [0x800001CE, "RUTA", "Rutanio"],
    [0x800001CF, "CSDT", "CSDT"],
    [0x800001D0, "ETI", "EtherInc"],
    [0x800001D1, "ZSLP", "Zclassic Simple Ledger Protocol"],
    [0x800001D2, "ERE", "EtherCore"],
    [0x800001D3, "DX", "DxChain Token"],
    [0x800001D4, "CPS", "Capricoin+"],
    [0x800001D5, "BTH", "Bithereum"],
    [0x800001D6, "MESG", "MESG"],
    [0x800001D7, "FIMK", "FIMK"],
    [0x800001D8, "AR", "Arweave"],
    [0x800001D9, "OGO", "Origo"],
    [0x800001DA, "ROSE", "Oasis Network"],
    [0x800001DB, "BARE", "BARE Network"],
    [0x800001DC, "GLEEC", "GleecBTC"],
    [0x800001DD, "CLR", "Color Coin"],
    [0x800001DE, "RNG", "Ring"],
    [0x800001DF, "OLO", "Tool Global"],
    [0x800001E0, "PEXA", "Pexa"],
    [0x800001E1, "MOON", "Mooncoin"],
    [0x800001E2, "OCEAN", "Ocean Protocol"],
    [0x800001E3, "BNT", "Bluzelle Native"],
    [0x800001E4, "AMO", "AMO Blockchain"],
    [0x800001E5, "FCH", "FreeCash"],
    [0x800001E6, "LAT", "PlatON"],
    [0x800001E7, "COIN", "Bitcoin Bank"],
    [0x800001E8, "VEO", "Amoveo"],
    [0x800001E9, "CCA", "Counos Coin"],
    [0x800001EA, "GFN", "Graphene"],
    [0x800001EB, "BIP", "Minter Network"],
    [0x800001EC, "KPG", "Kunpeng Network"],
    [0x800001ED, "FIN", "FINL Chain"],
    [0x800001EE, "BAND", "Band"],
    [0x800001EF, "DROP", "Dropil"],
    [0x800001F0, "BHT", "Bluehelix Chain"],
    [0x800001F1, "LYRA", "Scrypta"],
    [0x800001F2, "CS", "Credits"],
    [0x800001F3, "RUPX", "Rupaya"],
    [0x800001F4, "THETA", "Theta"],
    [0x800001F5, "SOL", "Solana"],
    [0x800001F6, "THT", "ThoughtAI"],
    [0x800001F7, "CFX", "Conflux"],
    [0x800001F8, "KUMA", "Kumacoin"],
    [0x800001F9, "HASH", "Provenance"],
    [0x800001FA, "CSPR", "Casper"],
    [0x800001FB, "EARTH", "EARTH"],
    [0x800001FC, "ERD", "Elrond"],
    [0x800001FD, "CHI", "Xaya"],
    [0x800001FE, "KOTO", "Koto"],
    [0x800001FF, "OTC", "θ"],
    [0x80000200, "XRD", "Radiant"],
    [0x80000201, "SEELEN", "Seele-N"],
    [0x80000202, "AETH", "AETH"],
    [0x80000203, "DNA", "Idena"],
    [0x80000204, "VEE", "Virtual Economy Era"],
    [0x80000205, "SIERRA", "SierraCoin"],
    [0x80000206, "LET", "Linkeye"],
    [0x80000207, "BSC", "Bitcoin Smart Contract"],
    [0x80000208, "BTCV", "BitcoinVIP"],
    [0x80000209, "ABA", "Dabacus"],
    [0x8000020A, "SCC", "StakeCubeCoin"],
    [0x8000020B, "EDG", "Edgeware"],
    [0x8000020C, "AMS", "AmsterdamCoin"],
    [0x8000020D, "GOSS", "GOSSIP Coin"],
    [0x8000020E, "BU", "BUMO"],
    [0x8000020F, "GRAM", "GRAM"],
    [0x80000210, "YAP", "Yapstone"],
    [0x80000211, "SCRT", "Secret Network"],
    [0x80000212, "NOVO", "Novo"],
    [0x80000213, "GHOST", "Ghost"],
    [0x80000214, "HST", "HST"],
    [0x80000215, "PRJ", "ProjectCoin"],
    [0x80000216, "YOU", "YOUChain"],
    [0x80000217, "XHV", "Haven Protocol"],
    [0x80000218, "BYND", "Beyondcoin"],
    [0x80000219, "JOYS", "Joys Digital"],
    [0x8000021A, "VAL", "Valorbit"],
    [0x8000021B, "FLOW", "Flow"],
    [0x8000021C, "SMESH", "Spacemesh Coin"],
    [0x8000021D, "SCDO", "SCDO"],
    [0x8000021E, "IQS", "IQ-Cash"],
    [0x8000021F, "BIND", "Compendia"],
    [0x80000220, "COINEVO", "Coinevo"],
    [0x80000221, "SCRIBE", "Scribe"],
    [0x80000222, "HYN", "Hyperion"],
    [0x80000223, "BHP", "BHP"],
    [0x80000224, "BBC", "BigBang Core"],
    [0x80000225, "MKF", "MarketFinance"],
    [0x80000226, "XDC", "XinFin.Network"],
    [0x80000227, "STR", "Straightedge"],
    [0x80000228, "SUM", "Sumcoin"],
    [0x80000229, "HBC", "HuobiChain"],
    [0x8000022A, "---", "reserved"],
    [0x8000022B, "BCS", "Bitcoin Smart"],
    [0x8000022C, "KTS", "Kratos"],
    [0x8000022D, "LKR", "Lkrcoin"],
    [0x8000022E, "TAO", "Tao"],
    [0x8000022F, "XWC", "Whitecoin"],
    [0x80000230, "DEAL", "DEAL"],
    [0x80000231, "NTY", "Nexty"],
    [0x80000232, "TOP", "TOP NetWork"],
    [0x80000233, "STARS", "Stargaze"],
    [0x80000234, "AG", "Agoric"],
    [0x80000235, "CICO", "Coinicles"],
    [0x80000236, "IRIS", "Irisnet"],
    [0x80000237, "NCG", "Nine Chronicles"],
    [0x80000238, "LRG", "Large Coin"],
    [0x80000239, "SERO", "Super Zero Protocol"],
    [0x8000023A, "BDX", "Beldex"],
    [0x8000023B, "CCXX", "Counos X"],
    [0x8000023C, "SLS", "Saluscoin"],
    [0x8000023D, "SRM", "Serum"],
    [0x8000023E, "---", "reserved"],
    [0x8000023F, "VIVT", "VIDT Datalink"],
    [0x80000240, "BPS", "BitcoinPoS"],
    [0x80000241, "NKN", "NKN"],
    [0x80000242, "ICL", "ILCOIN"],
    [0x80000243, "BONO", "Bonorum"],
    [0x80000244, "PLC", "PLATINCOIN"],
    [0x80000245, "DUN", "Dune"],
    [0x80000246, "DMCH", "Darmacash"],
    [0x80000247, "CTC", "Creditcoin"],
    [0x80000248, "KELP", "Haidai Network"],
    [0x80000249, "GBCR", "GoldBCR"],
    [0x8000024A, "XDAG", "XDAG"],
    [0x8000024B, "PRV", "Incognito Privacy"],
    [0x8000024C, "SCAP", "SafeCapital"],
    [0x8000024D, "TFUEL", "Theta Fuel"],
    [0x8000024E, "GTM", "Gentarium"],
    [0x8000024F, "RNL", "RentalChain"],
    [0x80000250, "GRIN", "Grin"],
    [0x80000251, "MWC", "MimbleWimbleCoin"],
    [0x80000252, "DOCK", "Dock"],
    [0x80000253, "POLYX", "Polymesh"],
    [0x80000254, "DIVER", "Divergenti"],
    [0x80000255, "XEP", "Electra Protocol"],
    [0x80000256, "APN", "Apron"],
    [0x80000257, "TFC", "Turbo File Coin"],
    [0x80000258, "UTE", "Unit-e"],
    [0x80000259, "MTC", "Metacoin"],
    [0x8000025A, "NC", "NobodyCash"],
    [0x8000025B, "XINY", "Xinyuehu"],
    [0x8000025C, "DYN", "Dynamo"],
    [0x8000025D, "BUFS", "Buffer"],
    [0x8000025E, "STOS", "Stratos"],
    [0x8000025F, "TON", "TON"],
    [0x80000260, "TAFT", "TAFT"],
    [0x80000261, "HYDRA", "HYDRA"],
    [0x80000262, "NOR", "Noir"],
    [0x80000263, "", "Manta Network Private Asset"],
    [0x80000264, "", "Calamari Network Private Asset"],
    [0x80000265, "WCN", "Widecoin"],
    [0x80000266, "OPT", "Optimistic Ethereum"],
    [0x80000267, "PSWAP", "PolkaSwap"],
    [0x80000268, "VAL", "Validator"],
    [0x80000269, "XOR", "Sora"],
    [0x8000026A, "SSP", "SmartShare"],
    [0x8000026B, "DEI", "DeimosX"],
    [0x8000026C, "---", "reserved"],
    [0x8000026D, "ZERO", "Singularity"],
    [0x8000026E, "ALPHA", "AlphaDAO"],
    [0x8000026F, "BDECO", "BDCashProtocol Ecosystem"],
    [0x80000270, "NOBL", "Nobility"],
    [0x80000271, "EAST", "Eastcoin"],
    [0x80000272, "KDA", "Kadena"],
    [0x80000273, "SOUL", "Phantasma"],
    [0x80000274, "LORE", "Gitopia"],
    [0x80000275, "FNR", "Fincor"],
    [0x80000276, "NEXUS", "Nexus"],
    [0x80000277, "QTZ", "Quartz"],
    [0x80000279, "CALL", "Callchain"],
    [0x8000027B, "POKT", "Pocket Network"],
    [0x8000027C, "EMIT", "EMIT"],
    [0x8000027D, "APTOS", "Aptos"],
    [0x8000027F, "BTSG", "BitSong"],
    [0x80000280, "LFC", "Leofcoin"],
    [0x80000281, "KCS", "KuCoin Shares"],
    [0x80000282, "KCC", "KuCoin Community Chain"],
    [0x80000283, "AZERO", "Aleph Zero"],
    [0x80000285, "LX", "Lynx"],
    [0x80000286, "XLN", "Lunarium"],
    [0x80000288, "ZRB", "Zarb"],
    [0x8000028A, "UCO", "Archethic"],
    [0x8000028F, "WMP", "WAMP"],
    [0x80000293, "KOIN", "Koinos"],
    [0x80000294, "PIRATE", "PirateCash"],
    [0x80000297, "SFRX", "EtherGem Sapphire"],
    [0x8000029A, "ACT", "Achain"],
    [0x8000029B, "PRKL", "Perkle"],
    [0x8000029C, "SSC", "SelfSell"],
    [0x8000029D, "GC", "GateChain"],
    [0x8000029E, "PLGR", "Pledger"],
    [0x8000029F, "MPLGR", "Pledger"],
    [0x800002A0, "KNOX", "Knox"],
    [0x800002A1, "ZED", "ZED"],
    [0x800002A2, "CNDL", "Candle"],
    [0x800002A3, "WLKR", "Walker Crypto Innovation Index"],
    [0x800002A4, "WLKRR", "Walker"],
    [0x800002A5, "YUNGE", "Yunge"],
    [0x800002A6, "Voken", "Voken"],
    [0x800002A7, "APL", "Apollo"],
    [0x800002A8, "Evrynet", "Evrynet"],
    [0x800002A9, "NENG", "Nengcoin"],
    [0x800002AA, "CHTA", "Cheetahcoin"],
    [0x800002AE, "KAR", "Karura Network"],
    [0x800002B0, "CET", "CoinEx Chain"],
    [0x800002B2, "KLV", "KleverChain"],
    [0x800002B6, "VTBC", "VTB Community"],
    [0x800002BA, "VEIL", "Veil"],
    [0x800002BB, "GTB", "GotaBit"],
    [0x800002BC, "XDAI", "xDai"],
    [0x800002BD, "COM", "Commercio.network"],
    [0x800002BE, "CCC", "Commercio.network"],
    [0x800002C3, "MCOIN", "Moneta Coin"],
    [0x800002C7, "CHC", "Chaincoin"],
    [0x800002C8, "SERF", "Serfnet"],
    [0x800002C9, "XTL", "Katal Chain"],
    [0x800002CA, "BNB", "Binance"],
    [0x800002CB, "SIN", "Sinovate"],
    [0x800002CC, "DLN", "Delion"],
    [0x800002CD, "BONTE", "Bontecoin"],
    [0x800002D5, "MCX", "MultiCash"],
    [0x800002DB, "BMK", "Bitmark"],
    [0x800002DE, "DENTX", "DENTNet"],
    [0x800002E1, "ATOP", "[Financial Blockchain]"],
    [0x800002EB, "CFG", "Centrifuge"],
    [0x800002EE, "XPRT", "Persistence"],
    [0x800002F5, "HONEY", "HoneyWood"],
    [0x80000300, "BALLZ", "Ballzcoin"],
    [0x80000302, "COSA", "Cosanta"],
    [0x80000303, "BR", "BR"],
    [0x80000307, "PLSR", "Pulsar Coin"],
    [0x80000309, "BTW", "Bitcoin World"],
    [0x8000030C, "PLCU", "PLC Ultima"],
    [0x8000030D, "PLCUX", "PLC Ultima X"],
    [0x80000310, "SUI", "Sui"],
    [0x80000312, "UIDD", "UIDD"],
    [0x80000313, "ACA", "Acala"],
    [0x80000314, "BNC", "Bifrost"],
    [0x80000315, "TAU", "Lamden"],
    [0x8000031F, "PDEX", "Polkadex"],
    [0x80000320, "BEET", "Beetle Coin"],
    [0x80000321, "DST", "DSTRA"],
    [0x80000328, "QVT", "Qvolta"],
    [0x80000329, "SDN", "Shiden Network"],
    [0x8000032A, "ASTR", "Astar Network"],
    [0x8000032B, "DVPN", "Sentinel"],
    [0x8000032D, "MEER", "Qitmeer"],
    [0x80000332, "VET", "VeChain Token"],
    [0x80000333, "REEF", "Reef"],
    [0x80000334, "CLO", "Callisto"],
    [0x80000336, "BDB", "BigchainDB"],
    [0x8000033C, "CCN", "ComputeCoin"],
    [0x8000033F, "CRUZ", "cruzbit"],
    [0x80000340, "SAPP", "Sapphire"],
    [0x80000341, "777", "Jackpot"],
    [0x80000342, "KYAN", "Kyanite"],
    [0x80000343, "AZR", "Azzure"],
    [0x80000344, "CFL", "CryptoFlow"],
    [0x80000345, "DASHD", "Dash Diamond"],
    [0x80000346, "TRTT", "Trittium"],
    [0x80000347, "UCR", "Ultra Clear"],
    [0x80000348, "PNY", "Peony"],
    [0x80000349, "BECN", "Beacon"],
    [0x8000034A, "MONK", "Monk"],
    [0x8000034B, "SAGA", "CryptoSaga"],
    [0x8000034C, "SUV", "Suvereno"],
    [0x8000034D, "ESK", "EskaCoin"],
    [0x8000034E, "OWO", "OneWorld Coin"],
    [0x8000034F, "PEPS", "PEPS Coin"],
    [0x80000350, "BIR", "Birake"],
    [0x80000351, "MOBIC", "MobilityCoin"],
    [0x80000352, "FLS", "Flits"],
    [0x80000354, "DSM", "Desmos"],
    [0x80000355, "PRCY", "PRCY Coin"],
    [0x80000362, "MOB", "MobileCoin"],
    [0x80000364, "IF", "Infinitefuture"],
    [0x80000370, "LUM", "Lum Network"],
    [0x80000373, "ZBC", "ZooBC"],
    [0x80000376, "ADF", "AD Token"],
    [0x80000378, "NEO", "NEO"],
    [0x80000379, "TOMO", "TOMO"],
    [0x8000037A, "XSEL", "Seln"],
    [0x80000380, "LKSC", "LKSCoin"],
    [0x80000382, "AS", "Assetchain"],
    [0x80000383, "XEC", "eCash"],
    [0x80000384, "LMO", "Lumeneo"],
    [0x80000388, "HNT", "Helium"],
    [0x8000038B, "FIS", "StaFi"],
    [0x8000038D, "SGE", "Saage"],
    [0x8000038F, "GERT", "Gert"],
    [0x80000394, "META", "Metadium"],
    [0x80000395, "FRA", "Findora"],
    [0x80000397, "CCD", "Concordium"],
    [0x8000039D, "DIP", "Dipper Network"],
    [0x800003A3, "RUNE", "THORChain (RUNE)"],
    [0x800003AD, "KCN", "Kylacoin"],
    [0x800003AE, "YCN", "Yilacoin"],
    [0x800003BB, "LTP", "LifetionCoin"],
    [0x800003BE, "", "KickSoccer"],
    [0x800003C6, "MATIC", "Matic"],
    [0x800003C8, "UNW", "UNW"],
    [0x800003CA, "TWINS", "TWINS"],
    [0x800003D1, "TLOS", "Telos"],
    [0x800003D9, "AU", "Autonomy"],
    [0x800003DB, "VCG", "VipCoin.Gold"],
    [0x800003DC, "XAZAB", "Xazab core"],
    [0x800003DD, "AIOZ", "AIOZ"],
    [0x800003DF, "PEC", "Phoenix"],
    [0x800003E1, "XRB", "X Currency"],
    [0x800003E2, "QUAI", "Quai Network"],
    [0x800003E4, "OKT", "OKChain Token"],
    [0x800003E5, "SUM", "Solidum"],
    [0x800003E6, "LBTC", "Lightning Bitcoin"],
    [0x800003E7, "BCD", "Bitcoin Diamond"],
    [0x800003E8, "BTN", "Bitcoin New"],
    [0x800003E9, "TT", "ThunderCore"],
    [0x800003EA, "BKT", "BanKitt"],
    [0x800003EB, "NODL", "Nodle"],
    [0x800003EC, "PCOIN", "PCOIN"],
    [0x800003EF, "FTM", "Fantom"],
    [0x800003F0, "RPG", "RPG"],
    [0x800003F2, "HT", "Huobi ECO Chain"],
    [0x800003F3, "ELV", "Eluvio"],
    [0x800003F5, "BIC", "Beincrypto"],
    [0x800003FC, "EVC", "Evrice"],
    [0x800003FE, "XRD", "Radix DLT"],
    [0x800003FF, "ONE", "HARMONY-ONE"],
    [0x80000400, "ONT", "Ontology"],
    [0x80000401, "CZZ", "Classzz"],
    [0x80000402, "KEX", "Kira Exchange Token"],
    [0x80000403, "MCM", "Mochimo"],
    [0x80000408, "BTCR", "BTCR"],
    [0x80000457, "BBC", "Big Bitcoin"],
    [0x80000460, "RISE", "RISE"],
    [0x80000462, "CMT", "CyberMiles Token"],
    [0x80000468, "ETSC", "Ethereum Social"],
    [0x80000469, "DFI", "DeFiChain"],
    [0x80000471, "$DAG", "Constellation Labs"],
    [0x80000479, "CDY", "Bitcoin Candy"],
    [0x80000483, "EFI", "Efinity"],
    [0x80000492, "HOO", "Hoo Smart Chain"],
    [0x800004D2, "ALPH", "Alephium"],
    [0x800004D5, "", "Nostr"],
    [0x80000504, "GLMR", "Moonbeam"],
    [0x80000505, "MOVR", "Moonriver"],
    [0x8000051C, "WEI", "WEI"],
    [0x80000539, "DFC", "Defcoin"],
    [0x80000575, "HYC", "Hycon"],
    [0x80000582, "TENTSLP", "TENT Simple Ledger Protocol"],
    [0x800005E6, "XSC", "XT Smart Chain"],
    [0x800005E8, "AAC", "Double-A Chain"],
    [0x800005F4, "", "Taler"],
    [0x800005FD, "BEAM", "Beam"],
    [0x80000650, "ELF", "AELF"],
    [0x80000652, "AUDL", "AUDL"],
    [0x80000654, "ATH", "Atheios"],
    [0x8000066A, "NEW", "Newton"],
    [0x80000679, "BTA", "Btachain"],
    [0x80000698, "BCX", "BitcoinX"],
    [0x800006C1, "XTZ", "Tezos"],
    [0x800006F0, "LBTC", "Liquid BTC"],
    [0x800006F1, "BBP", "Biblepay"],
    [0x800006F8, "JPYS", "JPY Stablecoin"],
    [0x800006FD, "VEGA", "Vega Protocol"],
    [0x80000717, "ADA", "Cardano"],
    [0x8000071A, "CUBE", "Cube Chain Native Token"],
    [0x80000743, "TES", "Teslacoin"],
    [0x80000760, "ZTX", "Zetrix"],
    [0x8000076B, "XEC", "eCash token"],
    [0x8000076D, "CLC", "Classica"],
    [0x8000077F, "VIPS", "VIPSTARCOIN"],
    [0x80000786, "CITY", "City Coin"],
    [0x800007A3, "XX", "xx coin"],
    [0x800007B9, "XMX", "Xuma"],
    [0x800007C0, "TRTL", "TurtleCoin"],
    [0x800007C3, "EGEM", "EtherGem"],
    [0x800007C5, "HODL", "HOdlcoin"],
    [0x800007C6, "PHL", "Placeholders"],
    [0x800007C7, "SC", "Sia"],
    [0x800007CC, "MYT", "Mineyourtime"],
    [0x800007CD, "POLIS", "Polis"],
    [0x800007CE, "XMCC", "Monoeci"],
    [0x800007CF, "COLX", "ColossusXT"],
    [0x800007D0, "GIN", "GinCoin"],
    [0x800007D1, "MNP", "MNPCoin"],
    [0x800007E1, "KIN", "Kin"],
    [0x800007E2, "EOSC", "EOSClassic"],
    [0x800007E3, "GBT", "GoldBean Token"],
    [0x800007E4, "PKC", "PKC"],
    [0x800007E5, "SKT", "Sukhavati"],
    [0x800007E6, "XHT", "Xinghuo Token"],
    [0x80000800, "MCASH", "MCashChain"],
    [0x80000801, "TRUE", "TrueChain"],
    [0x80000840, "IoTE", "IoTE"],
    [0x80000859, "XRG", "Ergon"],
    [0x80000888, "CHZ", "Chiliz"],
    [0x800008AD, "ASK", "ASK"],
    [0x800008ED, "", "Qiyi Chain"],
    [0x800008FD, "QTUM", "QTUM"],
    [0x800008FE, "ETP", "Metaverse"],
    [0x800008FF, "GXC", "GXChain"],
    [0x80000900, "CRP", "CranePay"],
    [0x80000901, "ELA", "Elastos"],
    [0x80000922, "SNOW", "Snowblossom"],
    [0x8000093D, "XIN", "Mixin"],
    [0x80000A0A, "AOA", "Aurora"],
    [0x80000A9E, "NAS", "Nebulas"],
    [0x80000B4E, "REOSC", "REOSC Ecosystem"],
    [0x80000B7D, "BND", "Blocknode"],
    [0x80000BBB, "LUX", "LUX"],
    [0x80000BD6, "XHB", "Hedera HBAR"],
    [0x80000C05, "COS", "Contentos"],
    [0x80000CCC, "CCC", "CodeChain"],
    [0x80000D05, "SXP", "Solar"],
    [0x80000D31, "ROI", "ROIcoin"],
    [0x80000D35, "DYN", "Dynamic"],
    [0x80000D37, "SEQ", "Sequence"],
    [0x80000DE0, "DEO", "Destocoin"],
    [0x80000DEC, "DST", "DeStream"],
    [0x80000E11, "CY", "Cybits"],
    [0x80000FC8, "FC8", "FCH Network"],
    [0x80001000, "YEE", "YeeCo"],
    [0x8000107A, "IOTA", "IOTA"],
    [0x8000107B, "SMR", "Shimmer"],
    [0x80001092, "AXE", "Axe"],
    [0x800010F7, "XYM", "Symbol"],
    [0x8000138E, "SBC", "Senior Block Coin"],
    [0x80001480, "FIC", "FIC"],
    [0x800014E9, "HNS", "Handshake"],
    [0x8000151C, "ISK", "ISKRA"],
    [0x8000155B, "ALTME", "ALTME"],
    [0x800015B3, "FUND", "Unification"],
    [0x8000167D, "STX", "Stacks"],
    [0x80001707, "VOW", "VowChain VOW"],
    [0x80001720, "SLU", "SILUBIUM"],
    [0x800017AC, "GO", "GoChain GO"],
    [0x8000181E, "MOI", "My Own Internet"],
    [0x800019C7, "RSC", "Royal Sports City"],
    [0x80001A0A, "BPA", "Bitcoin Pizza"],
    [0x80001A20, "SAFE", "SAFE"],
    [0x80001A7B, "COTI", "COTI"],
    [0x80001B39, "ROGER", "TheHolyrogerCoin"],
    [0x80001BB3, "TOPL", "Topl"],
    [0x80001CAD, "SHFT", "Shyft"],
    [0x80001E61, "BTV", "Bitvote"],
    [0x80001F40, "SKY", "Skycoin"],
    [0x80001F90, "", "DSRV"],
    [0x80002000, "PAC", "pacprotocol"],
    [0x80002019, "KLAY", "KLAY"],
    [0x80002093, "BTQ", "BitcoinQuark"],
    [0x800020FC, "XCH", "Chia"],
    [0x80002148, "---", "reserved"],
    [0x800022B8, "SBTC", "Super Bitcoin"],
    [0x80002304, "NULS", "NULS"],
    [0x80002327, "BTP", "Bitcoin Pay"],
    [0x80002328, "AVAX", "Avalanche"],
    [0x80002329, "ARB1", "Arbitrum"],
    [0x8000232A, "BOBA", "Boba"],
    [0x8000232B, "LOOP", "Loopring"],
    [0x8000232C, "STRK", "StarkNet"],
    [0x8000232D, "AVAXC", "Avalanche C-Chain"],
    [0x8000232E, "BSC", "Binance Smart Chain"],
    [0x80002645, "NRG", "Energi"],
    [0x800026A0, "BTF", "Bitcoin Faith"],
    [0x8000270F, "GOD", "Bitcoin God"],
    [0x80002710, "FO", "FIBOS"],
    [0x800027F2, "RTM", "Raptoreum"],
    [0x80002833, "XRC", "XRhodium"],
    [0x8000296D, "XPI", "Lotus"],
    [0x80002B67, "ESS", "Essentia One"],
    [0x80003039, "IPOS", "IPOS"],
    [0x8000312A, "MINA", "Mina"],
    [0x80003333, "BTY", "BitYuan"],
    [0x80003334, "YCC", "Yuan Chain Coin"],
    [0x80003DE5, "SDGO", "SanDeGo"],
    [0x80003F35, "XTX", "Totem Live Network"],
    [0x80004172, "ARDR", "Ardor"],
    [0x80004650, "MTR", "Meter"],
    [0x80004ADD, "SAFE", "Safecoin"],
    [0x80004ADF, "FLUX", "Flux"],
    [0x80004AE1, "RITO", "Ritocoin"],
    [0x80004E44, "XND", "ndau"],
    [0x8000520C, "C4EI", "c4ei"],
    [0x800057E8, "PWR", "PWRcoin"],
    [0x800062A4, "BELL", "Bellcoin"],
    [0x80006476, "CHX", "Own"],
    [0x80007531, "FLR", "Flare"],
    [0x8000797E, "ESN", "EtherSocial Network"],
    [0x80007A69, "", "ThePower.io"],
    [0x80008288, "TEO", "Trust Eth reOrigin"],
    [0x80008456, "BTCS", "Bitcoin Stake"],
    [0x80008888, "BTT", "ByteTrade"],
    [0x80009468, "FXTC", "FixedTradeCoin"],
    [0x80009999, "AMA", "Amabig"],
    [0x8000A455, "FACT", "FACT0RN"],
    [0x8000A814, "AXIV", "AXIV"],
    [0x8000C06E, "EVE", "evan.network"],
    [0x8000C0C0, "STASH", "STASH"],
    [0x8000CE10, "CELO", "Celo"],
    [0x8000F0B0, "TH", "TianHe"],
    [0x80010000, "KETH", "Krypton World"],
    [0x80010F2C, "GRLC", "Garlicoin"],
    [0x80011177, "GWL", "Gewel"],
    [0x80012FD1, "ZYN", "Wethio"],
    [0x80015B38, "RYO", "c0ban"],
    [0x8001869F, "WICC", "Waykichain"],
    [0x80018894, "HOME", "HomeCoin"],
    [0x80018A92, "STC", "Starcoin"],
    [0x80019A91, "STRAX", "Strax"],
    [0x80030FB1, "AKA", "Akroma"],
    [0x80011000, "GENOM", "GENOM"],
    [0x8003C301, "ATS", "ARTIS sigma1"],
    [0x8004CB2F, "PI", "Pi Network"],
    [0x80051614, "VALUE", "Value Chain"],
    [0x80051615, "3333", "Pi Value Consensus"],
    [0x80067932, "X42", "x42"],
    [0x800A2C2A, "VITE", "Vite"],
    [0x800D9038, "SEA", "Second Exchange Alliance"],
    [0x80100000, "AMAX", "Armonia Meta Chain"],
    [0x8011DF89, "ILT", "iOlite"],
    [0x8014095A, "ETHO", "Ether-1"],
    [0x80140ADC, "XERO", "Xerom"],
    [0x801A2010, "LAX", "LAPO"],
    [0x803BE02B, "EPK", "EPIK Protocol"],
    [0x80485944, "HYD", "Hydra Token"],
    [0x80501949, "BCO", "BitcoinOre"],
    [0x8050194A, "BHD", "BitcoinHD"],
    [0x8050544E, "PTN", "PalletOne"],
    [0x80564C58, "VLX", "Velas"],
    [0x8057414E, "WAN", "Wanchain"],
    [0x80579BFC, "WAVES", "Waves"],
    [0x80579BFD, "WEST", "Waves Enterprise"],
    [0x80616263, "ABC", "Abcmint"],
    [0x8063726D, "CRM", "Creamcoin"],
    [0x8073656D, "SEM", "Semux"],
    [0x80737978, "ION", "ION"],
    [0x8076ADF1, "FCT", "FirmaChain"],
    [0x80776772, "WGR", "WGR"],
    [0x80776773, "OBSR", "OBServer"],
    [0x807C8FC7, "AFS", "ANFS"],
    [0x80E6B280, "XDS", "XDS"],
    [0x83ADBC39, "AQUA", "Aquachain"],
    [0x854C5638, "HATCH", "Hatch"],
    [0x857AB1E1, "kUSD", "kUSD"],
    [0x85F5E0FC, "GENS", "GENS"],
    [0x85F5E0FD, "EQ", "EQ"],
    [0x85F5E0FE, "FLUID", "Fluid Chains"],
    [0x85F5E0FF, "QKC", "QuarkChain"],
    [0xA4465644, "FVDC", "ForumCoin"],
]


def coin_type(coin: str) -> int:
    """
    Return SLIP44 constant from coinSymbol or coinName
    """
    coin_code = list(
        filter(lambda c: c[1] == coin or c[2] == coin, SLIP44_CONSTANTS)
    )
    if coin_code:
        return coin_code[0][0]
    else:
        raise ValueError(f"not recognized: {coin}")
