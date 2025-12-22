
rule Trojan_Win64_Oyster_C_MTB{
	meta:
		description = "Trojan:Win64/Oyster.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 48 83 ec 20 48 8b 35 ?? ?? ?? ?? 48 8b 0e 48 8d ?? ?? ?? ?? 00 ba 01 00 00 00 45 31 c0 ff d0 b8 ?? ?? ?? ?? 48 03 06 48 83 c4 20 5e 48 ff e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}