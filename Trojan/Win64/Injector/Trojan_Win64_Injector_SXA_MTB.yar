
rule Trojan_Win64_Injector_SXA_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff c0 48 98 48 c7 44 24 ?? ?? ?? ?? ?? 4c 8b c8 4c 8d 45 50 48 8b 95 d8 01 00 00 48 8b 8d b8 01 00 00 ff 15 } //15
		$a_03_1 = {48 6b c0 01 48 8b 8d 18 04 00 00 48 8b 04 01 48 89 45 08 b8 ?? ?? ?? ?? 48 6b c0 ?? 48 8b 8d 18 04 00 00 48 8b 04 01 } //10
		$a_80_2 = {44 4c 4c 20 49 6e 6a 65 63 74 } //DLL Inject  1
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1) >=26
 
}