
rule Trojan_Win64_OysterLoader_GVA_MTB{
	meta:
		description = "Trojan:Win64/OysterLoader.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 0f 6e 44 04 ?? 66 0f 60 c0 66 0f 71 e0 08 66 0f d6 44 45 ?? 48 83 c0 04 48 3b c1 72 e2 } //2
		$a_02_1 = {0f be 4c 04 ?? 66 89 4c 45 ?? 48 ff c0 49 3b } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}