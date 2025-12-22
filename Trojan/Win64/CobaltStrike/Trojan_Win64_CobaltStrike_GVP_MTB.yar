
rule Trojan_Win64_CobaltStrike_GVP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 33 38 2e 31 39 30 2e 32 32 34 2e 36 33 3a 38 38 2f [0-10] 2e 65 78 65 } //3
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}