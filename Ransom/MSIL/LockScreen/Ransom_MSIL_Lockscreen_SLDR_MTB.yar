
rule Ransom_MSIL_Lockscreen_SLDR_MTB{
	meta:
		description = "Ransom:MSIL/Lockscreen.SLDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b b4 00 00 04 72 3e 0d 00 70 72 42 0d 00 70 6f 84 01 00 0a 72 46 0d 00 70 28 87 01 00 0a 0a 1b 8d 63 00 00 01 25 16 72 ?? 0e 00 70 a2 25 17 72 ?? 0e 00 70 a2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}