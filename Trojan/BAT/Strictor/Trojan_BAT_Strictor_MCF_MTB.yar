
rule Trojan_BAT_Strictor_MCF_MTB{
	meta:
		description = "Trojan:BAT/Strictor.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 6a 67 30 50 6a 65 77 6d 56 45 69 31 48 63 42 70 4c 2e 5a 34 4f 70 51 38 5a 33 6f 75 } //1 Njg0PjewmVEi1HcBpL.Z4OpQ8Z3ou
		$a_01_1 = {45 65 73 77 78 6d 73 72 6c 6c } //1 Eeswxmsrll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}