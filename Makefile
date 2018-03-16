INSTALLDIR=$(SFLAGENT_LIBDIR)
PROGNAME=libcuckoohash.a
C_FLAGSA += -fPIC -Werror -I$(SFLAGENT_SRCDIR)/src/include/ 
LD_FLAGS += -L$(SFLAGENT_INSDIR)/lib

all:
	gcc -g -c libcuckoohash.c $(C_FLAGSA)
	ar rcs $(PROGNAME) *.o 
	cp $(PROGNAME) $(INSTALLDIR) -a

install: all
	cp $(PROGNAME) $(INSTALLDIR) -a
test:
	gcc -g test.c -o test_hash $(C_FLAGSA) $(LD_FLAGS) -lcuckoohash -lringbuf
	
clean:
	rm -rf *.o *.a test_hash $(INSTALLDIR)/$(PROGNAME)
