
rule Trojan_BAT_FormBook_AOKB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AOKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 07 09 19 5f 07 8e 69 5d 94 1f 11 5a 61 0d 11 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}