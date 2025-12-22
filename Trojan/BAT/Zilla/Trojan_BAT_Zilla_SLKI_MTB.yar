
rule Trojan_BAT_Zilla_SLKI_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 06 e2 00 00 06 73 1f 00 00 0a 73 20 00 00 0a 25 17 6f 21 00 00 0a 6f 23 00 00 0a 7e 7b 01 00 04 72 91 05 00 70 28 2b 00 00 0a 39 86 00 00 00 28 cf 00 00 0a 72 90 06 00 70 28 33 00 00 0a 0c 7e cf 01 00 04 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}