include ../Makefile.inc

.PHONY: all clean

clean:
	rm -fr html latex $(PLUGIN_NAME).pdf

all: clean doxygen.conf
	@echo "Updating version..."
	@sed -r "s/^([[:space:]]*PROJECT_NUMBER[[:space:]]*=).*/\1 $(VERSION)/" doxygen.conf > doxygen.conf.temp
	@echo "Generating HTML pages..."
	@doxygen doxygen.conf.temp
	@rm doxygen.conf.temp
	@echo "Generating PDF..."
	@make -C latex -s > /dev/null 2>&1
	@mv latex/refman.pdf $(PLUGIN_NAME).pdf
	@rm -fr latex
	@echo "Done"
