
rule _#PUA_Block_XMRig{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 22 69 64 22 3a 25 6c 6c 64 2c 22 6a 73 6f 6e 72 70 63 22 3a 22 32 2e 30 22 2c 22 6d 65 74 68 6f 64 22 3a 22 6b 65 65 70 61 6c 69 76 65 64 22 2c 22 70 61 72 61 6d 73 22 3a 7b 22 69 64 22 3a 22 25 73 22 7d 7d } //2 {"id":%lld,"jsonrpc":"2.0","method":"keepalived","params":{"id":"%s"}}
		$a_01_1 = {6d 69 6e 65 72 } //1 miner
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule _#PUA_Block_XMRig_2{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {58 4d 52 69 67 20 6d 69 6e 65 72 } //1 XMRig miner
		$a_81_1 = {41 4d 44 47 50 55 } //1 AMDGPU
		$a_81_2 = {64 6f 6e 61 74 65 2e 73 73 6c 2e 78 6d 72 69 67 2e 63 6f 6d } //1 donate.ssl.xmrig.com
		$a_81_3 = {6e 6f 20 61 63 74 69 76 65 20 70 6f 6f 6c 73 2c 20 73 74 6f 70 20 6d 69 6e 69 6e 67 } //1 no active pools, stop mining
		$a_81_4 = {63 61 6e 27 74 20 72 65 73 75 6d 65 20 77 68 69 6c 65 20 6f 6e 20 62 61 74 74 65 72 79 20 70 6f 77 65 72 } //1 can't resume while on battery power
		$a_81_5 = {6e 76 6d 6c 44 65 76 69 63 65 47 65 74 46 61 6e 53 70 65 65 64 } //1 nvmlDeviceGetFanSpeed
		$a_81_6 = {70 6f 6f 6c 5f 77 61 6c 6c 65 74 } //1 pool_wallet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule _#PUA_Block_XMRig_3{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {55 52 4c 20 6f 66 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72 } //1 URL of mining server
		$a_81_1 = {70 61 73 73 77 6f 72 64 20 66 6f 72 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72 } //1 password for mining server
		$a_81_2 = {61 6c 67 6f 72 69 74 68 6d 20 50 6f 57 20 76 61 72 69 61 6e 74 } //1 algorithm PoW variant
		$a_81_3 = {63 72 79 70 74 6f 6e 69 67 68 74 } //1 cryptonight
		$a_81_4 = {6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //1 minergate.com
		$a_81_5 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 57 } //1 MapVirtualKeyW
		$a_81_6 = {50 61 79 6c 6f 61 64 20 54 6f 6f 20 4c 61 72 67 65 } //1 Payload Too Large
		$a_81_7 = {53 65 74 57 69 6e 45 76 65 6e 74 48 6f 6f 6b } //1 SetWinEventHook
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule _#PUA_Block_XMRig_4{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 78 6d 72 69 67 20 5b 4f 50 54 49 4f 4e 53 5d } //10 Usage: xmrig [OPTIONS]
		$a_01_1 = {63 72 79 70 74 6f 6e 69 67 68 74 } //1 cryptonight
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //2 cryptonight-lite
		$a_01_3 = {6d 61 78 69 6d 75 6d 20 43 50 55 20 75 73 61 67 65 20 66 6f 72 20 61 75 74 6f 6d 61 74 69 63 20 74 68 72 65 61 64 73 6d 6f 64 65 } //3 maximum CPU usage for automatic threadsmode
		$a_01_4 = {70 72 69 6e 74 20 68 61 73 68 72 61 74 65 20 72 65 70 6f 72 74 20 65 76 65 72 79 20 4e 20 73 65 63 6f 6e 64 73 } //4 print hashrate report every N seconds
		$a_01_5 = {70 6f 72 74 20 66 6f 72 20 74 68 65 20 6d 69 6e 65 72 20 41 50 49 } //5 port for the miner API
		$a_01_6 = {65 6e 61 62 6c 65 20 6e 69 63 65 68 61 73 68 2f 78 6d 72 69 67 2d 70 72 6f 78 79 } //6 enable nicehash/xmrig-proxy
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*4+(#a_01_5  & 1)*5+(#a_01_6  & 1)*6) >=25
 
}
rule _#PUA_Block_XMRig_5{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 78 6d 72 69 67 } //10 Usage: xmrig
		$a_01_1 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 68 65 61 76 79 } //1 cryptonight-heavy
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 75 6c 74 72 61 6c 69 74 65 } //2 cryptonight-ultralite
		$a_01_3 = {78 6d 72 2e 70 6f 6f 6c } //2 xmr.pool
		$a_81_4 = {58 4d 52 69 67 20 43 50 55 20 6d 69 6e 65 72 } //2 XMRig CPU miner
		$a_01_5 = {6e 6f 20 61 63 74 69 76 65 20 70 6f 6f 6c 73 2c 20 73 74 6f 70 20 6d 69 6e 69 6e 67 } //2 no active pools, stop mining
		$a_01_6 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6d 6f 6e 65 72 6f } //3 cryptonight-monero
		$a_01_7 = {6d 69 6e 65 72 67 61 74 65 } //3 minergate
		$a_01_8 = {63 72 79 70 74 6f 6e 69 67 68 74 5f 74 75 72 74 6c 65 } //4 cryptonight_turtle
		$a_01_9 = {63 72 79 70 74 6f 6e 69 67 68 74 2f 67 70 75 } //5 cryptonight/gpu
		$a_01_10 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //6 stratum+tcp://
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_81_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*4+(#a_01_9  & 1)*5+(#a_01_10  & 1)*6) >=33
 
}
rule _#PUA_Block_XMRig_6{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 78 6d 72 69 67 20 5b 4f 50 54 49 4f 4e 53 5d } //10 Usage: xmrig [OPTIONS]
		$a_01_1 = {65 6e 61 62 6c 65 20 6e 69 63 65 68 61 73 68 2f 78 6d 72 69 67 2d 70 72 6f 78 79 } //6 enable nicehash/xmrig-proxy
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 } //1 cryptonight
		$a_01_3 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //2 cryptonight-lite
		$a_01_4 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 67 68 74 } //2 cryptonight-light
		$a_01_5 = {6d 61 78 69 6d 75 6d 20 43 50 55 20 75 73 61 67 65 20 66 6f 72 20 61 75 74 6f 6d 61 74 69 63 20 74 68 72 65 61 64 73 6d 6f 64 65 } //3 maximum CPU usage for automatic threadsmode
		$a_01_6 = {70 72 69 6e 74 20 68 61 73 68 72 61 74 65 20 72 65 70 6f 72 74 20 65 76 65 72 79 20 4e 20 73 65 63 6f 6e 64 73 } //4 print hashrate report every N seconds
		$a_01_7 = {70 6f 72 74 20 66 6f 72 20 74 68 65 20 6d 69 6e 65 72 20 41 50 49 } //5 port for the miner API
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*3+(#a_01_6  & 1)*4+(#a_01_7  & 1)*5) >=27
 
}
rule _#PUA_Block_XMRig_7{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //2 .minergate.com
		$a_01_1 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //1 stratum+tcp://
		$a_01_2 = {2e 6e 69 63 65 68 61 73 68 2e 63 6f 6d } //1 .nicehash.com
		$a_01_3 = {7b 22 69 64 22 3a 25 6c 6c 64 2c 22 6a 73 6f 6e 72 70 63 22 3a 22 32 2e 30 22 2c 22 6d 65 74 68 6f 64 22 3a 22 6b 65 65 70 61 6c 69 76 65 64 22 2c 22 70 61 72 61 6d 73 22 3a 7b 22 69 64 22 3a 22 25 73 22 7d 7d } //1 {"id":%lld,"jsonrpc":"2.0","method":"keepalived","params":{"id":"%s"}}
		$a_01_4 = {61 66 66 69 6e 65 5f 74 6f 5f 63 70 75 } //1 affine_to_cpu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule _#PUA_Block_XMRig_8{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 76 69 64 69 61 } //1 nvidia
		$a_01_1 = {68 61 73 68 65 73 5f 74 6f 74 61 6c } //1 hashes_total
		$a_01_2 = {6d 65 6d 5f 63 6c 6f 63 6b } //1 mem_clock
		$a_01_3 = {77 6f 72 6b 65 72 5f 69 64 } //1 worker_id
		$a_01_4 = {63 72 79 70 74 6f 6e 69 67 68 74 5f 65 78 74 72 61 5f 63 70 75 } //1 cryptonight_extra_cpu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule _#PUA_Block_XMRig_9{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 70 75 2d 61 66 66 69 6e 69 74 79 } //1 cpu-affinity
		$a_01_1 = {64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 } //1 donate-over-proxy
		$a_01_2 = {72 69 67 2d 69 64 } //1 rig-id
		$a_01_3 = {6e 69 63 65 68 61 73 68 } //1 nicehash
		$a_01_4 = {64 6f 6e 61 74 65 2e 76 32 2e 78 6d 72 69 67 2e 63 6f 6d } //1 donate.v2.xmrig.com
		$a_01_5 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6d 6f 6e 65 72 6f 76 37 } //1 cryptonight-monerov7
		$a_01_6 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6d 6f 6e 65 72 6f 76 38 } //1 cryptonight-monerov8
		$a_01_7 = {63 72 79 70 74 6f 6e 69 67 68 74 5f 76 38 } //1 cryptonight_v8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#PUA_Block_XMRig_10{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {58 4d 52 69 67 20 32 2e 31 35 2e 31 2d 62 65 74 61 } //1 XMRig 2.15.1-beta
		$a_01_1 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //1 cryptonight-lite
		$a_01_2 = {72 69 67 20 69 64 65 6e 74 69 66 69 65 72 20 66 6f 72 20 70 6f 6f 6c 2d 73 69 64 65 20 73 74 61 74 69 73 74 69 63 73 } //1 rig identifier for pool-side statistics
		$a_01_3 = {72 75 6e 20 74 68 65 20 6d 69 6e 65 72 20 69 6e 20 74 68 65 20 62 61 63 6b 67 72 6f 75 6e 64 } //1 run the miner in the background
		$a_01_4 = {6e 69 63 65 68 61 73 68 2e 63 6f 6d 20 } //1 nicehash.com 
		$a_01_5 = {63 72 79 70 74 6f 6e 69 67 68 74 68 65 61 76 79 } //1 cryptonightheavy
		$a_01_6 = {6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //1 minergate.com
		$a_01_7 = {78 6d 72 2e 70 6f 6f 6c } //1 xmr.pool
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule _#PUA_Block_XMRig_11{
	meta:
		description = "!#PUA:Block:XMRig,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {65 6e 61 62 6c 65 20 6e 69 63 65 68 61 73 68 2e 63 6f 6d 20 73 75 70 70 6f 72 74 } //1 enable nicehash.com support
		$a_01_1 = {6d 69 6e 69 6e 67 20 61 6c 67 6f 72 69 74 68 6d 20 68 74 74 70 73 3a 2f 2f 78 6d 72 69 67 2e 63 6f 6d 2f 64 6f 63 73 2f 61 6c 67 6f 72 69 74 68 6d 73 } //1 mining algorithm https://xmrig.com/docs/algorithms
		$a_01_2 = {75 73 65 20 64 61 65 6d 6f 6e 20 52 50 43 20 69 6e 73 74 65 61 64 20 6f 66 20 70 6f 6f 6c 20 66 6f 72 20 73 6f 6c 6f 20 6d 69 6e 69 6e 67 } //1 use daemon RPC instead of pool for solo mining
		$a_01_3 = {70 61 74 68 20 74 6f 20 43 55 44 41 20 70 6c 75 67 69 6e 20 28 78 6d 72 69 67 2d 63 75 64 61 2e 64 6c 6c 20 6f 72 20 6c 69 62 78 6d 72 69 67 2d 63 75 64 61 2e 73 6f 29 } //1 path to CUDA plugin (xmrig-cuda.dll or libxmrig-cuda.so)
		$a_01_4 = {72 75 6e 20 74 68 65 20 6d 69 6e 65 72 20 69 6e 20 74 68 65 20 62 61 63 6b 67 72 6f 75 6e 64 } //1 run the miner in the background
		$a_01_5 = {65 78 74 72 61 5f 6e 6f 6e 63 65 } //1 extra_nonce
		$a_01_6 = {70 6f 6f 6c 5f 77 61 6c 6c 65 74 } //1 pool_wallet
		$a_01_7 = {6e 76 6d 6c 44 65 76 69 63 65 47 65 74 46 61 6e 53 70 65 65 64 } //1 nvmlDeviceGetFanSpeed
		$a_01_8 = {6e 76 6d 6c 44 65 76 69 63 65 47 65 74 54 65 6d 70 65 72 61 74 75 72 65 } //1 nvmlDeviceGetTemperature
		$a_01_9 = {64 6f 6e 61 74 65 2e 73 73 6c 2e 78 6d 72 69 67 2e 63 6f 6d } //1 donate.ssl.xmrig.com
		$a_01_10 = {64 6f 6e 61 74 65 2e 76 32 2e 78 6d 72 69 67 2e 63 6f 6d } //1 donate.v2.xmrig.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}