
rule Trojan_BAT_NjRat_MCJ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.MCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 65 73 00 43 72 65 61 74 65 00 53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d 00 73 65 74 5f 4b 65 } //1 敁s牃慥整匀浹敭牴捩汁潧楲桴m敳彴敋
		$a_01_1 = {78 75 79 2e 65 78 65 00 4c 6f 61 64 65 72 00 6d 73 63 6f 72 6c 69 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}