
rule _#PUA_Block_XMRStak{
	meta:
		description = "!#PUA:Block:XMRStak,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 74 68 6d 69 6e 65 72 2e 65 78 65 } //1 ethminer.exe
		$a_01_1 = {4e 76 4f 70 74 69 6d 75 73 45 6e 61 62 6c 65 6d 65 6e 74 43 75 64 61 } //1 NvOptimusEnablementCuda
		$a_03_2 = {4c 6f 63 61 6c 5c 7b [0-25] 7d 2d 6f 6e 63 65 2d 66 6c 61 67 } //1
		$a_01_3 = {78 6d 72 73 74 61 6b 5f 73 74 61 72 74 5f 62 61 63 6b 65 6e 64 } //2 xmrstak_start_backend
		$a_01_4 = {43 3a 2f 55 73 65 72 73 2f 41 75 73 74 69 6e 20 46 65 6c 69 70 65 2f 44 6f 63 75 6d 65 6e 74 73 2f 50 72 6f 6a 65 74 6f 73 2f 6d 69 6e 65 72 2f 78 6d 72 73 74 61 6b 2f 62 61 63 6b 65 6e 64 2f 6e 76 69 64 69 61 2f 6e 76 63 63 5f 63 6f 64 65 2f 63 75 64 61 5f 65 78 74 72 61 2e 63 75 } //1 C:/Users/Austin Felipe/Documents/Projetos/miner/xmrstak/backend/nvidia/nvcc_code/cuda_extra.cu
		$a_01_5 = {00 78 6d 72 73 74 61 6b 5f 63 75 64 61 5f 62 61 63 6b 65 6e 64 } //1
		$a_01_6 = {43 3a 5c 55 73 65 72 73 5c 4d 41 49 4e 5c 78 6d 72 2d 73 74 61 6b 2d 64 65 70 2d 62 75 69 6c 64 5c 6c 69 62 6d 69 63 72 6f 68 74 74 70 64 } //3 C:\Users\MAIN\xmr-stak-dep-build\libmicrohttpd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3) >=3
 
}
rule _#PUA_Block_XMRStak_2{
	meta:
		description = "!#PUA:Block:XMRStak,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 61 6c 6c 65 74 5f 61 64 64 72 65 73 73 } //1 wallet_address
		$a_01_1 = {70 6f 6f 6c 5f 70 61 73 73 77 6f 72 64 } //1 pool_password
		$a_01_2 = {6e 69 63 65 68 61 73 68 5f 6e 6f 6e 63 65 } //1 nicehash_nonce
		$a_01_3 = {50 6f 6f 6c 2d 73 69 64 65 20 68 61 73 68 65 73 } //1 Pool-side hashes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}