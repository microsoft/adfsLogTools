# Pester Tests for AdfsEventsModule

## Pester Overview

This project includes a set of [Pester](https://github.com/pester/Pester) tests to ensure the basic functionality of the AdfsEventsModule script. 

To run the tests, you must have Pester version 4.x or higher installed on the machine you will run ```Get-ADFSEvents``` from. 
For more information on installing Pester, see their [installation instructions](https://github.com/pester/Pester/wiki/Installation-and-Update). 

Once Pester is installed, you can copy the test file and script to the same location, and run the following: 

    cd <directory containing tests and script>
    Invoke-Pester -Script .\Test.AdfsEventsModule.ps1

## Side Effects 

The testing module will create a Relying Party Trust on your machine, which will be used for generating request logs. 
You should manually remove the Relying Party when you have completed testing. 

## Test Matrix 

