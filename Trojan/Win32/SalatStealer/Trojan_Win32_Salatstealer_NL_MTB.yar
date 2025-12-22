
rule Trojan_Win32_Salatstealer_NL_MTB{
	meta:
		description = "Trojan:Win32/Salatstealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 4d 30 6d ?? ec 48 d1 62 ?? 18 c4 16 54 } //2
		$a_01_1 = {09 ce 4b 08 ce 32 37 59 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}