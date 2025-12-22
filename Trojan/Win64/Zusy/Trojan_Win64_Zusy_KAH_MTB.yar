
rule Trojan_Win64_Zusy_KAH_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 da 08 ca 89 d9 20 c1 30 c3 08 cb 89 d9 30 d1 84 db } //20
		$a_03_1 = {0f af d0 89 d0 44 31 e8 89 ?? ?? ?? ?? 83 e2 01 09 ?? 31 d0 85 d0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}