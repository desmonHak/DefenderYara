
rule Trojan_BAT_PhantomStealer_APN_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.APN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 1b 11 19 1d 5d 1f 1f 5f 62 11 19 1f 61 5a 61 61 13 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}