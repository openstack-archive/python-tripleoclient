=========
overcloud
=========

Overcloud v1

overcloud deploy
----------------

Deploy an overcloud stack

.. program:: overcloud deploy
.. code:: bash

    os overcloud deploy
        --stack [STACK_NAME]
        --templates [TEMPLATES]
        [-t <TIMEOUT>]
        [--control-scale CONTROL_SCALE]
        [--compute-scale COMPUTE_SCALE]
        [--ceph-storage-scale CEPH_STORAGE_SCALE]
        [--block-storage-scale BLOCK_STORAGE_SCALE]
        [--swift-storage-scale SWIFT_STORAGE_SCALE]
        [--control-flavor CONTROL_FLAVOR]
        [--compute-flavor COMPUTE_FLAVOR]
        [--ceph-storage-flavor CEPH_STORAGE_FLAVOR]
        [--block-storage-flavor BLOCK_STORAGE_FLAVOR]
        [--swift-storage-flavor SWIFT_STORAGE_FLAVOR]
        [--libvirt-type LIBVIRT_TYPE]
        [--ntp-server NTP_SERVER] [--cinder-lvm]
        [--no-proxy NO_PROXY] [-O <OUTPUT DIR>]
        [-e <HEAT ENVIRONMENT FILE>] [--rhel-reg]
        [--reg-method {satellite,portal}]
        [--reg-org REG_ORG] [--reg-force]
        [--reg-sat-url REG_SAT_URL]
        [--reg-activation-key REG_ACTIVATION_KEY]
        [--answers-file <ANSWERS FILE>]

.. option:: --stack <stack_name>

    Optionally rename stack from default of 'overcloud'. Currently, only one
    stack is supported.

.. option:: --templates <directory>

    The directory containing the Heat templates to deploy.

.. option:: -t <timeout>, --timeout <timeout>

    Deployment timeout in minutes (default: 240)

.. option:: --control-scale <scale-amount>

    New number of control nodes.

.. option:: --compute-scale <scale-amount>

    New number of compute nodes.

.. option:: --ceph-storage-scale <scale-amount>

    New number of ceph storage nodes.

.. option:: --block-storage-scale <scale-amount>

    New number of block storage nodes.

.. option:: --swift-storage-scale <scale-amount>

    New number of swift storage nodes.

.. option:: --control-flavor <flavor-name>

    Nova flavor to use for control nodes.

.. option:: --compute-flavor <flavor-name>

    Nova flavor to use for compute nodes.

.. option:: --ceph-storage-flavor <flavor-name>

    Nova flavor to use for ceph storage nodes.

.. option:: --block-storage-flavor <flavor-name>

    Nova flavor to use for cinder storage nodes.

.. option:: --swift-storage-flavor <flavor-name>

    Nova flavor to use for swift storage nodes.

.. option:: --libvirt-type {kvm,qemu}

    Libvirt domain type. (default: kvm)

.. option:: --ntp-server <ip-address>

    The NTP for overcloud nodes.

.. option:: --no-proxy <hosts>

    A comma separated list of hosts that should not be proxied.

.. option:: -e <file>, --environment-file <file>

    Environment files to be passed to the heat stack-create or heat
    stack-update command. (Can be specified more than once.)

.. option:: --rhel-reg

    Register overcloud nodes to the customer portal or a satellite.

.. option:: --reg-method [sattelite|portal]

    RHEL registration method to use for the overcloud nodes.

.. option:: --reg-org <organization>

    Organization key to use for registration.

.. option:: --reg-force

    Register the system even if it is already registered.

.. option:: --reg-sat-url <url>

    Satellite server to register overcloud nodes.

.. option:: --reg-activation-key <key>

    Activation key to use for registration.

.. option:: --answers-file <file>

    Point to a file that specifies a templates directory and a list
    of environment files in YAML format::

        templates: ~/templates
        environments:
          - ~/test-env1.yaml
          - ~/test-env2.yaml
          - ~/test-env3.yaml
