# Ultimo MVC ACL Synology
Synology Diskstation Authentication using ACL for Ultimo MVC

## Requirements
* PHP 5.3
* Ultimo Synology DS

## Usage
### Register plugin
	$application->addPlugin(new \ultimo\security\mvc\plugins\synology\ds\Authorizer());