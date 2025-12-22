
rule Trojan_Win32_OffLoader_PGOF_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 6f 6f 66 63 61 6b 65 73 2e 69 6e 66 6f 2f 6d 61 72 6b 2e 70 68 70 } //roofcakes.info/mark.php  2
		$a_80_1 = {76 65 73 74 73 68 65 65 74 2e 78 79 7a 2f 6d 61 72 6b 73 2e 70 68 70 } //vestsheet.xyz/marks.php  2
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}
rule Trojan_Win32_OffLoader_PGOF_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 66 72 61 6d 65 73 74 6f 76 65 2e 69 6e 66 6f 2f 61 6a 74 6f 2e 70 68 70 3f } //http://framestove.info/ajto.php?  2
		$a_80_1 = {68 74 74 70 3a 2f 2f 6a 6f 69 6e 66 61 6c 6c 2e 78 79 7a 2f 61 6a 74 6f 73 2e 70 68 70 3f } //http://joinfall.xyz/ajtos.php?  2
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}
rule Trojan_Win32_OffLoader_PGOF_MTB_3{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 61 72 6d 79 74 72 65 61 74 6d 65 6e 74 2e 69 6e 66 6f 2f 79 74 72 69 2e 70 68 70 3f } //http://armytreatment.info/ytri.php?  2
		$a_80_1 = {68 74 74 70 3a 2f 2f 61 72 6d 72 6f 75 74 65 2e 78 79 7a 2f 79 74 72 69 73 2e 70 68 70 3f } //http://armroute.xyz/ytris.php?  2
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
		$a_80_3 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}
rule Trojan_Win32_OffLoader_PGOF_MTB_4{
	meta:
		description = "Trojan:Win32/OffLoader.PGOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 70 6f 72 74 65 72 2e 69 6e 66 6f 2f 6e 69 65 63 2e 70 68 70 3f } //http://exampleporter.info/niec.php?  2
		$a_80_1 = {68 74 74 70 3a 2f 2f 68 6f 6e 65 79 73 68 69 72 74 2e 78 79 7a 2f 6e 69 65 63 73 2e 70 68 70 3f } //http://honeyshirt.xyz/niecs.php?  2
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
		$a_80_3 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}