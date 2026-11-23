.PHONY: all build deb clean install test

all: deb

build:
	python3 build_deb.py

deb:
	python3 build_deb.py

clean:
	rm -f *.deb
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

install: deb
	dpkg -i pve-gic-manager_1.0.0_all.deb

test:
	systemctl status pve-gic-manager.service
	curl -s http://127.0.0.1:8004/api/v1/health
