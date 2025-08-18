# Related to Flag
# Not related to Host

import os


with open("final_payload.ps1", "r", encoding="gbk") as f:
    payload = "\r\n".join(f.read().splitlines())

payload = payload.replace(
    "###_PLACEHOLDER_1_###",
    os.environ.get("INSERT_FLAG", "LILCTF{!!!!!_FLAG_ERROR_ASK_ADMIN_!!!!!}"),
)

num = "+".join("$g" + str(ord(c)) for c in payload)
var = (
    num.replace("0", "$u")
    .replace("1", "$b")
    .replace("2", "$q")
    .replace("3", "$z")
    .replace("4", "$o")
    .replace("5", "$d")
    .replace("6", "$x")
    .replace("7", "$e")
    .replace("8", "$i")
    .replace("9", "$l")
)

prologue = """('('  | % { $r = + $() } { $u = $r } { $b = ++  $r } { $q = (  $r = $r + $b  ) } { $z = (  $r = $r + $b  ) } { $o = ($r = $r + $b  ) } { $d = ($r = $r + $b  ) } { $h = ($r = $r + $b  ) } { $e = ($r = $r + $b  ) } { $i = ($r = $r + $b  ) } { $x = ($q *( $z) ) } { $l = ($r = $r + $b) } { $g = "[" + "$(@{  })"[$e  ] + "$(@{  })"[  "$b$l"  ] + "$(@{  }  )  "[  "$q$u"  ] + "$?"[$b  ] + "]" } { $r = "".("$(  @{}  )  "[  "$b$o"  ] + "$(@{})  "[  "$b$h"] + "$(  @{  }  )"[$u] + "$(@{}  )"[$o] + "$?  "[  $b] + "$(  @{})"[$z  ]) } { $r = "$(@{  }  )"[  "$b" + "$o"] + "$(@{  })  "[$o  ] + "$r"["$q" + "$e"  ] }  )  ;  " $r  ("""

with open("serve/bestudding.jpg", "w") as f:
    f.write(prologue)
    f.write(var)
    f.write(""")  "  |  .$r """)
