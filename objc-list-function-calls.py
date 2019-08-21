import r2pipe
import sys

function = sys.argv[1]
r2 = r2pipe.open(sys.argv[2])
r2.cmd('aa')
r2.cmd('s ' + function)
nslog_addr = hex(r2.cmdj("is.j")["symbols"]["vaddr"])
nslog_xrefs = r2.cmdj("axtj")
classes = list()
print(nslog_addr)
for i in nslog_xrefs:
    objc_class = i.get("flag")
    if objc_class:
        if "class" in objc_class:
            objc_class_name = objc_class.split(".")[2]
        else:
            objc_class_name = objc_class.split(".")[1]
        if objc_class_name not in classes:
            classes.append(objc_class_name)
    print("class: {}".format(i.get("flag")))
    print("class address: {}".format(hex(i.get("fcn_addr"))))
    print("function name: {}".format(i.get("fcn_name")))
    print("instruction address: {}".format(hex(i.get("from"))))
    print("instruction: {}".format(i.get("opcode")))
    print("instruction type: {}".format(i.get("type")))
    print("")
print("{} references found!".format(len(nslog_xrefs)))

print("{} classes found!".format(len(classes)))
for i in classes:
    print(i)
r2.quit()
