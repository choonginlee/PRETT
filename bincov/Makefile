BUILDDIR=_build

all: $(BUILDDIR) linking building

$(BUILDDIR):
	mkdir $@

linking: $(BUILDDIR) dynamorio/clients/bincov

dynamorio/clients/bincov:
	ln -sf `pwd`/bincov `pwd`/dynamorio/clients/bincov

building: linking
	cd $(BUILDDIR); cmake ../dynamorio
	make -C $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) dynamorio/clients/bincov

.PHONY: all linking building clean
