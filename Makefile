print-%: ; @echo $*=$($*)

.PHONY: all prod run clean

#-------------------------------------------------------------------------------
# Variables
#-------------------------------------------------------------------------------

OPENSSL     := /usr/include/openssl
OPENSSL_LIB := -lssl

SOURCES := $(shell find . -type f -name *.cpp -or -name *.c)
OBJECTS := $(SOURCES:.cpp=.o)
OBJECTS := $(OBJECTS:.c=.o)

CPPFLAGS := -I./src -I./lib -I$(OPENSSL)
CXXFLAGS := $(CPPFLAGS) -MMD -MP -std=c++0x
LDFLAGS  := $(OPENSSL_LIB) -lcrypto -lpthread
CXX      := clang++

EXEC_FLAGS :=
EXEC       := jwtcrack

#-------------------------------------------------------------------------------
# Main Program
#-------------------------------------------------------------------------------

all: CXXFLAGS += -DDEBUG -g -Wall
all: $(EXEC)

prod: CXXFLAGS += -DNDEBUG -O3
prod: $(EXEC)

-include $(SOURCES:.cpp=.d)

$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	@echo Compiling $<...
	$(CXX) -o $@ -c $(CXXFLAGS) $<

$(EXEC): $(OBJECTS)
	@echo
	@echo Linking $@...
	$(CXX) -o $@ $(OBJECTS) $(LDFLAGS)

run: all prod
	@echo
	./$(EXEC) eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE


#-------------------------------------------------------------------------------
# Clean
#-------------------------------------------------------------------------------

clena: clean
clean:
	find -type f -name "*.[o|d]" | xargs rm -f
	rm -f $(EXEC)
