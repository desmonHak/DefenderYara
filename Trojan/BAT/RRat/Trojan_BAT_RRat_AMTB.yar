
rule Trojan_BAT_RRat_AMTB{
	meta:
		description = "Trojan:BAT/RRat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {31 30 35 36 36 64 38 36 2d 36 34 30 66 2d 34 33 32 32 2d 38 38 37 33 2d 62 63 34 66 62 61 65 36 33 64 39 39 } //10566d86-640f-4322-8873-bc4fbae63d99  2
		$a_80_1 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //kLjw4iIsCLsZtxc4lksN0j  2
		$a_80_2 = {33 65 34 66 39 61 33 35 2d 38 39 64 66 2d 34 61 36 35 2d 39 61 62 37 2d 30 65 65 66 61 30 33 33 30 39 62 36 } //3e4f9a35-89df-4a65-9ab7-0eefa03309b6  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}
rule Trojan_BAT_RRat_AMTB_2{
	meta:
		description = "Trojan:BAT/RRat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {33 38 31 36 33 39 38 39 2e 65 78 65 } //38163989.exe  2
		$a_80_1 = {36 30 35 35 35 37 30 38 34 38 32 35 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //605557084825.My.Resources  2
		$a_80_2 = {75 39 65 63 30 35 32 62 64 61 66 37 38 34 62 62 61 39 64 38 35 61 37 37 66 66 35 35 32 38 61 33 61 } //u9ec052bdaf784bba9d85a77ff5528a3a  2
		$a_80_3 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //kLjw4iIsCLsZtxc4lksN0j  2
		$a_80_4 = {44 69 73 61 62 6c 65 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e } //DisableAuthentication  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}