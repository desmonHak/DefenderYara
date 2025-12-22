
rule Trojan_Win32_GodRat_C_MTB{
	meta:
		description = "Trojan:Win32/GodRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c } //3
		$a_03_1 = {8b f8 85 ff 0f 84 ?? ?? ?? ?? 8b cf 85 ?? 74 ?? 8b 55 ?? 2b d7 0f 1f 80 00 00 00 00 8a 04 0a 8d 49 01 88 41 ff 83 ee 01 75 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}