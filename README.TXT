Ozone Widgeting Framework Security Project

**********************************************************************

SAMPLE SECURITY PROJECTS

We ship with 4 sample security projects.  Each security project has an 
associated Spring XML Configuration file. 

1.  Default, x509 fallback to CAS
2.  CAS only
3.  x509 only
4.  x509/LDAP

**********************************************************************

HOW TO SWITCH BETWEEN SECURITY PROJECTS

1.  Choose the spring configuration file that maps to the sample of your
    choice.  The four samples and associated spring configuration files are:
       - Default,  x509 fallback to CAS  OWFsecurityContext.xml
       - CAS only  OWFsecurityContext_CAS_only.xml
       - x509 only OWFsecurityContext_cert_only.xml
       - x509/LDAP OWFsecurityContext_cert_ldap.xml
    Take that spring configuration file and copy it into the jetty/resources
    directory.  Delete any other spring configuration files in there, such
    as the default OWFSecurityContext.xml.

2.  If you delete cas.war from the webapps directory in jetty, remember
    to delete the associated cas-context.xml from the jetty context's directory.  

3.  If you are trying out the x509/LDAP sample, our sample is designed to work with
    Apache DS installed on localhost and running on the default port, 10389.  You can 
    download Apache DS from http://directory.apache.org/ and install it.  There are 
    directions on the Apache DS website on how to install and run the Apache DS server.

    If you want to connect to ldap at some url other than localhost:10389, the url is defined
    in the OWFSecurityContext_cert_ldap.xml spring config file.  Adjust it there.

    Next, for the LDAP sample, we have included a sample Apache DS server.xml file, called
    \owf-security\owf-security-project\src\main\resources\conf\apache-ds-server.xml.  The one
    change it has in it is the requirement that you add the partition owf-1.  To do that, 
    add the xml line <jdbmPartition id="owf-1" suffix="o=Ozone,l=Columbia,st=Maryland,c=US" /> to 
    the XPATH spring:beans/defaultDirectoryService/partitions as shown in the example file. 

    Now, you need to load our sample data into your directory service.  We have provided a sample
    ldif file, called \owf-security\owf-security-project\src\main\resources\conf\testUsers.ldif.  The
    Apache DS site explains how to load the ldif file.  Hint--download the Apache Directory Studio!
     
    Restart your directory service to make sure all changes are applied.

4.  Start up OWF.  Authenticate. 



**********************************************************************

HOW TO BUILD THE PROJECT 

It is not required that you build the project in order to test the different samples.  
But we provide the source code and scripts to do the build.

From the main directory, do: 

ant

The default target in build.xml will build and create the sample security 
project in the target directory, called owf-security.jar.  This jar 
contains all four security samples.  


**********************************************************************
