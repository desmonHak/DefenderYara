
rule Trojan_Win32_Dridex_ADR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 89 45 f0 6a 0a 68 e8 03 00 00 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 34 89 45 e8 50 ff 75 08 } //3
		$a_03_1 = {68 49 73 75 7a 54 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 75 ?? 6a 00 8d 93 } //2
		$a_01_2 = {68 61 6e 5f 74 68 30 39 5f 63 68 63 31 37 63 68 6d 5f 65 64 68 75 5f 61 63 68 69 73 75 7a } //1 han_th09_chc17chm_edhu_achisuz
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}