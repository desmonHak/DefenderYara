
rule _#PUA_Block_CpuMulti{
	meta:
		description = "!#PUA:Block:CpuMulti,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 70 75 6d 69 6e 65 72 2d 6d 75 6c 74 69 } //3 cpuminer-multi
		$a_01_1 = {63 70 75 6d 69 6e 65 72 2d 63 6f 6e 66 2e 6a 73 6f 6e } //2 cpuminer-conf.json
		$a_01_2 = {54 61 6e 67 75 79 20 50 72 75 76 6f 74 } //1 Tanguy Pruvot
		$a_01_3 = {75 73 65 72 6e 61 6d 65 3a 70 61 73 73 77 6f 72 64 20 70 61 69 72 20 66 6f 72 20 6d 69 6e 69 6e 67 20 73 65 72 76 65 72 } //1 username:password pair for mining server
		$a_01_4 = {63 6f 69 6e 62 61 73 65 2d 61 64 64 72 } //1 coinbase-addr
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}