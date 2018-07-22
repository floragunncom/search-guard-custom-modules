# Search Guard Custom Modules

<p align="center">
<img src="http://docs.search-guard.com/latest/search-guard-frontmatter.png" style="width: 60%" class="md_image"/>
</p>

## About this Module

This project provides you sample code for custom authentication/authorization modules.

## Installation

If you want to play around or test this sample project feel free to do so. Please follow the instructions below for the installation and use of this project.

Download and import:

* clone or download this repository
* import the cloned/downloaded folder into your IDE as a Maven project
  * e.g. in eclipse go to `File>Import > Maven > Existing Maven Projects` and follow the next steps
* make changes to the code if you want to and save the changes

Installation into an elasticsearch environment:

* install [Maven](https://maven.apache.org/download.cgi) for command line if you haven't already
* `cd` into your search-guard-custom-modules project folder
* use `mvn package` to compile the code
* copy the search-guard-custom-modules.jar that has no `-test` at the end of the name form `<custom/modules/project/path>/target/` and paste it into `<elasticsearch/installation/path>/plugins/search-guard-<version>/`
* start/restart elasticsearch
* make some changes in the sgconfig if needed

For further information visit the [search-guard docs](https://docs.search-guard.com/latest/custom-authentication-modules).