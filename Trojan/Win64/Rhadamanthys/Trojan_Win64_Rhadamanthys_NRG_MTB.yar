
rule Trojan_Win64_Rhadamanthys_NRG_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6e ca 66 0f 70 c9 00 f3 41 0f 6f 02 49 83 c2 10 66 0f ef c1 41 0f 11 42 } //2
		$a_01_1 = {48 0f af d1 48 c1 ea 24 8d 14 92 c1 e2 02 29 d0 83 f8 13 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}