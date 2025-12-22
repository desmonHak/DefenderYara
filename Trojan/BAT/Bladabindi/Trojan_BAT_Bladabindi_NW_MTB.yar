
rule Trojan_BAT_Bladabindi_NW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 74 ?? 00 00 1b 16 1f 3a 9d 11 04 75 ?? 00 00 1b 20 } //2
		$a_03_1 = {13 04 11 04 74 ?? 00 00 1b 16 1f 3a 9d 11 04 75 ?? 00 00 1b 6f ?? 00 00 0a 17 9a } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Bladabindi_NW_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 2d 11 2b 1f 2d 0d 16 2d f6 2b 1b 2b 1c 2b 1d 2b 1e 2b 0a 2b 21 2b 22 } //1
		$a_01_1 = {9d a2 3f 09 1f 00 00 00 98 00 33 00 16 00 00 01 00 00 00 c2 00 00 00 2d 00 00 00 48 01 00 00 f7 00 00 00 b9 00 00 00 5d 01 00 00 34 } //1
		$a_01_2 = {32 38 30 64 61 35 34 65 32 33 34 34 } //1 280da54e2344
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}