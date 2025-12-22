
rule Trojan_Win32_Urelas_AB_MTB{
	meta:
		description = "Trojan:Win32/Urelas.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b e8 c6 06 e9 8b 43 0c 89 46 01 6a 04 68 00 10 00 00 ff 73 08 51 ?? ?? ?? 8b d0 8b 73 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}