
rule Trojan_Win64_Dridex_KAD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 2f 8b c3 48 33 c8 48 ff c7 0f b6 c1 8b cb c1 e9 08 ?? ?? ?? ?? 33 d9 48 3b fe 7c } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}