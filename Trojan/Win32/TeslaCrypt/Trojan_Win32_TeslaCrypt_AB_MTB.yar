
rule Trojan_Win32_TeslaCrypt_AB_MTB{
	meta:
		description = "Trojan:Win32/TeslaCrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 4c 24 10 66 8b 14 41 66 89 d6 66 83 ?? ?? 66 89 d7 66 83 c7 ?? 66 83 fe ?? 66 0f 42 d7 8b 5c 24 30 66 39 14 43 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}