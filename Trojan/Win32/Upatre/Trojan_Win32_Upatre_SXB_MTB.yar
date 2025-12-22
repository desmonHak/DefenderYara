
rule Trojan_Win32_Upatre_SXB_MTB{
	meta:
		description = "Trojan:Win32/Upatre.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 41 18 ff d0 8b 84 24 f8 01 00 00 8b 08 8d 94 24 f4 04 00 00 52 50 8b 41 1c ff d0 8b 94 24 f4 04 00 00 } //3
		$a_03_1 = {31 0f af 44 24 ?? 03 c6 03 84 24 ?? ?? ?? ?? f7 d8 4b 89 44 24 ?? 75 ca } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}