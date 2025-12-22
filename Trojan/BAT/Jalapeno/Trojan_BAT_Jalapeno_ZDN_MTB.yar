
rule Trojan_BAT_Jalapeno_ZDN_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1b 11 1c 1f 61 5a 61 13 1d 00 02 11 1a 11 1c 6f ?? 00 00 0a 13 1e 04 03 6f ?? 00 00 0a 59 13 1f 11 1f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}