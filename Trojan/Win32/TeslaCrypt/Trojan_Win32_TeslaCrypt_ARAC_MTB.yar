
rule Trojan_Win32_TeslaCrypt_ARAC_MTB{
	meta:
		description = "Trojan:Win32/TeslaCrypt.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c c5 00 00 00 00 c1 e8 1d 0b c1 a3 ?? ?? ?? ?? 8a 0a 80 c9 20 80 c9 20 88 4d 0c 8b 4d 0c 81 e1 ff 00 00 00 33 c1 42 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 80 3a 00 75 c8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}