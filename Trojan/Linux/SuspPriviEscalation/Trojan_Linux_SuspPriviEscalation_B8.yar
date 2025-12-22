
rule Trojan_Linux_SuspPriviEscalation_B8{
	meta:
		description = "Trojan:Linux/SuspPriviEscalation.B8,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 64 00 20 00 2d 00 69 00 20 00 22 00 31 00 65 00 20 00 65 00 78 00 65 00 63 00 20 00 } //2 sed -i "1e exec 
		$a_00_1 = {73 00 65 00 64 00 20 00 2d 00 6e 00 20 00 22 00 31 00 65 00 20 00 65 00 78 00 65 00 63 00 20 00 } //2 sed -n "1e exec 
		$a_00_2 = {62 00 75 00 69 00 6c 00 64 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 67 00 72 00 61 00 64 00 6c 00 65 00 } //-4 buildscript.gradle
		$a_00_3 = {62 00 75 00 69 00 6c 00 64 00 2e 00 67 00 72 00 61 00 64 00 6c 00 65 00 } //-4 build.gradle
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*-4+(#a_00_3  & 1)*-4) >=4
 
}