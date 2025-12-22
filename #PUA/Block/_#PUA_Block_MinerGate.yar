
rule _#PUA_Block_MinerGate{
	meta:
		description = "!#PUA:Block:MinerGate,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d } //2 minergate.com
		$a_01_1 = {2e 6d 69 6e 65 72 73 5f 6c 6f 63 6b } //2 .miners_lock
		$a_01_2 = {63 72 79 70 74 6f 6e 69 67 68 74 2d 6c 69 74 65 } //1 cryptonight-lite
		$a_01_3 = {65 74 68 65 72 65 75 6d } //1 ethereum
		$a_01_4 = {4e 76 4f 70 74 69 6d 75 73 45 6e 61 62 6c 65 6d 65 6e 74 43 75 64 61 } //1 NvOptimusEnablementCuda
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}