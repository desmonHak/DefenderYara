
rule Trojan_Win64_Maranhao_GAS_MTB{
	meta:
		description = "Trojan:Win64/Maranhao.GAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_81_0 = {61 70 69 2e 6d 61 72 61 6e 68 61 6f 67 61 6e 67 2e 66 75 6e } //8 api.maranhaogang.fun
	condition:
		((#a_81_0  & 1)*8) >=8
 
}