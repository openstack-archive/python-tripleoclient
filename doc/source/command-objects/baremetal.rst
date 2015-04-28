=========
baremetal
=========

Baremetal v1

baremetal import
----------------

Import baremetal nodes

.. program:: baremetal import
.. code:: bash

    os baremetal import
        [ --service-host <service_host> ]
        [ --json | --csv ]
        <file_in>

.. option:: --service-host <service_host>

    Nova compute service host to register nodes with (default None)

.. option:: --json

    Input file is in json format

.. option:: --csv

    Input file is in csv format

.. _baremetal_import-file_in:
.. describe:: <file_in>

    Filename to be imported

baremetal introspection all start
---------------------------------

Begin introspection of all baremetal nodes

.. program:: baremetal introspection all start
.. code:: bash

    os baremetal introspection all start

baremetal introspection all status
----------------------------------

Get status of node introspection

.. program:: baremetal introspection all status
.. code:: bash

    os baremetal introspection all status

baremetal configure boot
------------------------

Configure boot devices for all baremetal nodes

.. program:: baremetal configure boot
.. code:: bash

    os baremetal configure boot
