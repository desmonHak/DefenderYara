
rule Trojan_BAT_Jalapeno_ZEM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 72 01 00 00 70 28 ?? 00 00 0a 72 04 02 00 70 6f ?? 00 00 0a 1f 64 73 05 00 00 0a 1f 10 6f ?? 00 00 0a 28 ?? 00 00 0a 72 46 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 17 73 08 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}