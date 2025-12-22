
rule Trojan_BAT_Jalapeno_BV_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 20 21 16 03 04 61 07 20 62 5b 87 5e 60 0b 02 07 20 21 69 01 32 5c 0b fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}