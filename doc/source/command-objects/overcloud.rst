=========
overcloud
=========

Overcloud v1

overcloud deploy stack
----------------------

Deploy an overcloud stack

.. program:: overcloud deploy stack
.. code:: bash

    os overcloud deploy stack
        [ --control-scale <scale-amount> ]
        [ --compute-scale <scale-amount> ]
        [ --ceph-storage-scale <scale-amount> ]
        [ --block-storage-scale <scale-amount> ]
        [ --swift-storage-scale <scale-amount> ]

.. option:: --control-scale <scale-amount>

    New number of control nodes (default 0)

.. option:: --compute-scale <scale-amount>

    New number of compute nodes (default 0)

.. option:: --ceph-storage-scale <scale-amount>

    New number of ceph storage nodes (default 0)

.. option:: --block-storage-scale <scale-amount>

    New number of block storage nodes (default 0)

.. option:: --swift-storage-scale <scale-amount>

    New number of swift storage nodes (default 0)
