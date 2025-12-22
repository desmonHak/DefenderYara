
rule Trojan_Win64_LummaStealer_GAPR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 bd 32 6c fe de 17 33 d0 ff 61 4b 8b 41 5f 12 05 14 c4 11 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}