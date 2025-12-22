
rule Ransom_Win64_PrincessLocker_CD_MTB{
	meta:
		description = "Ransom:Win64/PrincessLocker.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 69 74 69 63 61 6c 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 78 66 69 6c 74 72 61 74 65 64 2e 20 20 } //5 Critical data has been exfiltrated.  
		$a_01_1 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 } //5 Your network infrastructure has been compromised
		$a_01_2 = {46 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //5 Files have been encrypted
		$a_01_3 = {2e 6f 6e 69 6f 6e 2f 63 68 61 74 } //5 .onion/chat
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=20
 
}