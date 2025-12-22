
rule Trojan_Win64_Radthief_KK_MTB{
	meta:
		description = "Trojan:Win64/Radthief.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 d0 48 f7 e9 48 01 ca 48 d1 fa 49 89 c9 48 c1 f9 ?? 48 29 ca 48 8d 14 52 4d 89 ca 49 29 d1 49 39 f0 } //20
		$a_03_1 = {49 89 d0 48 f7 ea 48 c1 fa ?? 48 69 d2 ?? ?? 00 00 4d 89 c1 49 29 d0 49 8d 90 90 ?? ?? 00 00 48 39 d1 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}