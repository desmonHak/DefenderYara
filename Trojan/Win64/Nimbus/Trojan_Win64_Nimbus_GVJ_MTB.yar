
rule Trojan_Win64_Nimbus_GVJ_MTB{
	meta:
		description = "Trojan:Win64/Nimbus.GVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 69 c9 ?? ?? ?? ?? 42 32 44 05 fb 42 88 44 05 9b 4d 8d 40 01 b8 03 00 00 00 f7 e1 8b c1 2b c2 d1 e8 03 c2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}