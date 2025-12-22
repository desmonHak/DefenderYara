
rule Trojan_Win32_Guloader_NSU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.NSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {73 75 70 72 61 6f 70 74 69 6f 6e 61 6c 2e 6f 76 65 } //1 supraoptional.ove
		$a_81_1 = {44 65 73 6d 6f 6e 63 75 73 31 37 33 2e 53 70 72 } //1 Desmoncus173.Spr
		$a_81_2 = {68 61 72 70 79 69 61 2e 63 6f 70 } //1 harpyia.cop
		$a_81_3 = {62 72 79 67 67 65 72 69 73 2e 62 6f 77 } //1 bryggeris.bow
		$a_81_4 = {61 66 6d 72 6b 65 2e 6b 79 6c } //1 afmrke.kyl
		$a_81_5 = {53 74 72 61 66 66 65 65 6b 73 70 65 64 69 74 69 6f 6e 32 39 2e 77 6f 6c } //1 Straffeekspedition29.wol
		$a_81_6 = {41 63 75 61 65 73 74 68 65 73 69 61 2e 65 70 69 } //1 Acuaesthesia.epi
		$a_81_7 = {6b 76 69 6e 64 65 65 6d 61 6e 63 69 70 61 74 69 6f 6e 65 6e 73 20 6c 69 70 6f 67 72 61 6d 6d 61 74 69 63 } //1 kvindeemancipationens lipogrammatic
		$a_81_8 = {6f 72 6c 6f 6e 65 74 20 65 6e 64 6e 6f 74 65 73 } //1 orlonet endnotes
		$a_81_9 = {6e 6f 72 64 62 6f 20 67 65 6f 6d 65 74 72 69 63 69 7a 65 } //1 nordbo geometricize
		$a_81_10 = {62 72 73 6b 75 72 73 65 72 73 } //1 brskursers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}