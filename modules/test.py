import pefile
pe = pefile.PE(sys.argv[1])
print "Import Hash: %s" % pe.get_imphash()
