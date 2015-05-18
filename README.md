# FiScripts
I'll drop here some useful scripts to do things.

Before running some of the Scripts, you must set the openstack variables, or exec your own "keystonerc" file:

   export OS_AUTH_URL=xxx
   export OS_USERNAME=xxx
   export OS_PASSWORD=xxx
   export OS_TENANT_NAME=xxx
   export OS_REGION_NAME=xxx


vview
------
This script needs the Openstack environment variables set, it's only purpose is to connect to the remote virtual host:
     view <vm_id>

It only works in linux :(


