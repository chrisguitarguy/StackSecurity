.PHONY: test

test:
	php vendor/bin/phpunit

unittest:
	php vendor/bin/phpunit --group unit

inttest:
	php vendor/bin/phpunit --group integration
