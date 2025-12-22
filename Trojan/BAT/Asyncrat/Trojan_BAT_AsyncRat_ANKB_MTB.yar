
rule Trojan_BAT_AsyncRat_ANKB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ANKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 4a 07 8e 69 5d 1d 58 1f 0e 58 1f 16 59 1f 18 58 1f 17 59 91 61 02 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 02 8e 69 5d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}