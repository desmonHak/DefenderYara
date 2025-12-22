
rule Trojan_Win64_BlueSpinach_A{
	meta:
		description = "Trojan:Win64/BlueSpinach.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 41 8b d9 49 8b f8 48 8b f2 48 8b e9 e8 4b 00 00 00 48 8b 0d ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8d 81 ?? ?? ?? ?? ff d0 48 8b 05 ?? ?? ?? ?? 44 8b cb 48 05 ?? ?? ?? ?? 4c 8b c7 48 8b d6 48 8b cd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}