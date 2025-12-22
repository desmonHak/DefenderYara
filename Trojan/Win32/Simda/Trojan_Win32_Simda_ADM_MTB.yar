
rule Trojan_Win32_Simda_ADM_MTB{
	meta:
		description = "Trojan:Win32/Simda.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0e 8b 56 04 03 55 f4 83 c4 0c 8d 45 fc 50 8b 45 08 51 57 52 50 ff 15 ?? ?? ?? ?? 68 00 80 00 00 6a 00 57 } //2
		$a_03_1 = {88 48 0a c7 45 fc 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 1f 68 14 32 40 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 0d 8d 55 fc 52 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}