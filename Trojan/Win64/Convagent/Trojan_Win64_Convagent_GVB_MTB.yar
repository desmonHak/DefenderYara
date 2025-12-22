
rule Trojan_Win64_Convagent_GVB_MTB{
	meta:
		description = "Trojan:Win64/Convagent.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 39 34 2e 32 36 2e 31 39 32 2e 39 34 3a 37 37 37 37 2f 62 6c 61 63 6b 6c 69 73 74 } //2 ://194.26.192.94:7777/blacklist
		$a_01_1 = {2e 65 78 65 68 69 6a 61 63 6b 65 64 } //1 .exehijacked
		$a_01_2 = {63 68 61 63 68 61 32 30 } //1 chacha20
		$a_01_3 = {46 69 6c 65 20 73 61 76 65 64 20 74 6f 3a 20 } //1 File saved to: 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}