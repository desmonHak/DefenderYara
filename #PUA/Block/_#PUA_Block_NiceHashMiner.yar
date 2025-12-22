
rule _#PUA_Block_NiceHashMiner{
	meta:
		description = "!#PUA:Block:NiceHashMiner,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 69 63 65 48 61 73 68 4d 69 6e 65 72 2e 43 6f 6e 66 69 67 73 2e 44 61 74 61 } //1 NiceHashMiner.Configs.Data
		$a_01_1 = {47 65 74 4e 69 63 65 48 61 73 68 41 70 69 44 61 74 61 } //1 GetNiceHashApiData
		$a_01_2 = {67 65 74 5f 4d 69 6e 65 72 44 65 76 69 63 65 4e 61 6d 65 } //1 get_MinerDeviceName
		$a_01_3 = {6e 69 63 65 68 61 73 68 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //1 nicehash_credentials
		$a_01_4 = {4e 69 63 65 48 61 73 68 4d 69 6e 65 72 2e 4d 69 6e 65 72 73 } //1 NiceHashMiner.Miners
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
rule _#PUA_Block_NiceHashMiner_2{
	meta:
		description = "!#PUA:Block:NiceHashMiner,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 69 63 65 48 61 73 68 2f 45 78 63 61 76 61 74 6f 72 } //1 NiceHash/Excavator
		$a_01_1 = {65 78 63 61 76 61 74 6f 72 5f 63 75 64 61 5f 76 65 72 } //1 excavator_cuda_ver
		$a_01_2 = {47 50 55 20 4d 69 6e 65 72 20 66 6f 72 20 4e 69 63 65 48 61 73 68 } //1 GPU Miner for NiceHash
		$a_01_3 = {51 55 49 43 4b 4d 49 4e 45 52 20 63 70 75 20 6d 69 6e 69 6e 67 20 65 6e 61 62 6c 65 } //1 QUICKMINER cpu mining enable
		$a_01_4 = {51 55 49 43 4b 4d 49 4e 45 52 20 63 70 75 20 6d 69 6e 69 6e 67 20 64 69 73 61 62 6c 65 } //1 QUICKMINER cpu mining disable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}