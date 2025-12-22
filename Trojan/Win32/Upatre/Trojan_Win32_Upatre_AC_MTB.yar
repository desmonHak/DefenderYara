
rule Trojan_Win32_Upatre_AC_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 56 56 56 68 a8 20 40 00 ff 15 ?? ?? ?? ?? 89 45 e4 3b c6 ?? ?? ?? ?? ?? ?? 8b 3d 5c 20 40 00 56 56 6a 03 56 56 68 ?? ?? 00 00 68 d0 20 40 00 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}