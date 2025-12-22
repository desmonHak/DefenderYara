
rule Trojan_Win32_Injector_MKA_MTB{
	meta:
		description = "Trojan:Win32/Injector.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 c1 bc 00 ee c0 bc 00 6c 69 62 63 75 72 6c 2e } //15
		$a_01_1 = {40 a6 25 00 d0 08 01 00 80 36 06 00 ac 68 24 } //10
		$a_01_2 = {ac 68 24 00 34 c0 bc 00 41 c0 bc 00 50 c0 bc } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}