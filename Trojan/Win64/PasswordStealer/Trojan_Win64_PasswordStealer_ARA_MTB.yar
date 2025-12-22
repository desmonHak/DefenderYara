
rule Trojan_Win64_PasswordStealer_ARA_MTB{
	meta:
		description = "Trojan:Win64/PasswordStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 25 07 00 00 80 7d 07 ff c8 83 c8 f8 ff c0 48 98 48 8d 0d ?? ?? ?? ?? 0f be 0c 08 0f be 45 cf 03 c8 81 e1 7f 00 00 80 7d 07 ff c9 83 c9 80 ff c1 30 4c 15 d0 48 ff c2 48 83 fa 1c 72 c1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}