
rule Trojan_Linux_Mirai_AMTB{
	meta:
		description = "Trojan:Linux/Mirai!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {66 75 73 65 72 20 2d 6b 20 2d 6e 20 74 63 70 20 25 64 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //fuser -k -n tcp %d 2>/dev/null  1
		$a_80_1 = {4e 46 6e 68 69 46 53 44 66 64 73 66 46 53 44 } //NFnhiFSDfdsfFSD  1
		$a_80_2 = {5b 6c 6f 63 6b 65 72 5d 20 66 63 6e 74 6c 20 46 5f 47 45 54 46 4c } //[locker] fcntl F_GETFL  1
		$a_80_3 = {5b 6c 6f 63 6b 65 72 5d 20 66 63 6e 74 6c 20 46 5f 53 45 54 46 4c } //[locker] fcntl F_SETFL  1
		$a_80_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //npxXoudifFeEgGaACScs  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule Trojan_Linux_Mirai_AMTB_2{
	meta:
		description = "Trojan:Linux/Mirai!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 72 6f 75 74 65 72 2e 6c 62 6c 69 6e 6b 2d 72 65 70 2e 73 68 } //wget http://%s/router.lblink-rep.sh  2
		$a_80_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 64 76 72 2e 6c 69 6c 69 6e 2d 72 65 70 2e 73 68 } //wget http://%s/dvr.lilin-rep.sh  2
		$a_80_2 = {62 6f 79 6d 6f 64 65 72 2e 64 64 6e 73 2e 6e 65 74 } //boymoder.ddns.net  3
		$a_80_3 = {24 28 77 67 65 74 24 7b 49 46 53 7d 68 74 74 70 3a 2f 2f 25 73 2f 64 76 72 2e 74 76 74 2d 72 65 70 2e 73 68 } //$(wget${IFS}http://%s/dvr.tvt-rep.sh  3
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=10
 
}