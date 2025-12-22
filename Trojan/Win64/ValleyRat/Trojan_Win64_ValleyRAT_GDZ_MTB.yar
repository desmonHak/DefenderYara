
rule Trojan_Win64_ValleyRAT_GDZ_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.GDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 04 01 00 00 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8d 15 fc 22 00 00 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 89 05 47 46 00 00 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d 15 e7 22 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 0d 27 46 00 00 48 8d 15 e0 22 00 00 48 89 05 f9 45 00 00 ff 15 } //10
		$a_80_1 = {5c 5f 5c 5f 5c 64 6f 63 75 6d 65 6e 74 2e 62 61 74 } //\_\_\document.bat  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}