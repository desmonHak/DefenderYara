
rule Trojan_MacOS_AmosStealz_B_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealz.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {65 00 6c 00 65 00 63 00 74 00 72 00 75 00 6e 00 } //1 electrun
		$a_00_1 = {65 00 78 00 6f 00 64 00 75 00 73 00 } //1 exodus
		$a_00_2 = {44 00 6f 00 67 00 65 00 63 00 6f 00 69 00 6e 00 } //1 Dogecoin
		$a_00_3 = {43 00 6f 00 69 00 6e 00 6f 00 6d 00 69 00 } //1 Coinomi
		$a_00_4 = {29 00 72 00 65 00 61 00 64 00 77 00 72 00 69 00 74 00 65 00 28 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 26 00 } //1 )readwrite(profile &
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}