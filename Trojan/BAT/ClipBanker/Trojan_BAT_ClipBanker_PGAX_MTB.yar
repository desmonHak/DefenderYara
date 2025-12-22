
rule Trojan_BAT_ClipBanker_PGAX_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PGAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {49 4c 6f 76 65 59 6f 75 72 4d 6f 74 68 65 72 } //ILoveYourMother  2
		$a_80_1 = {6b 74 6f 20 70 72 6f 63 68 69 74 61 6c 20 74 6f 74 20 73 68 6c 75 68 61 } //kto prochital tot shluha  1
		$a_80_2 = {55 73 65 72 4f 4f 42 45 42 72 6f 6b 65 72 2e 65 78 65 } //UserOOBEBroker.exe  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2) >=5
 
}