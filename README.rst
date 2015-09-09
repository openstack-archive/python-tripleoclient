=============
tripleoclient
=============

OpenStackClient reference plugin module

The OSC plugin system is designed so that the plugin need only be
properly installed for OSC to find and use it.  It utilizes the
``setuptools`` entry points mechanism to advertise to OSC the
plugin module and supported commands.

**tripleoclient** is an OpenStackClient (OSC) plugin implementation that
implements commands useful for TripleO and the install and management of
both an undercloud and an overcloud.

Discovery
=========

OSC discovers extensions by enumerating the entry points found under
``openstack.cli.extension`` and initializing the given client module.

::

    [entry_points]
    openstack.cli.extension =
        oscplugin = oscplugin.plugin

The client module must implement the following interface functions:

* ``API_NAME`` - A string containing the plugin API name; this is
  the name of the entry point declaring the plugin client module
  (``oscplugin = ...`` in the example above) and the group name for
  the plugin commands (``openstack.oscplugin.v1 =`` in the example below)
* ``API_VERSION_OPTION`` (optional) - If set, the name of the API
  version attribute; this must be a valid Python identifier and
  match the destination set in ``build_option_parser()``.
* ``API_VERSIONS`` - A dict mapping a version string to the client class
* ``build_option_parser(parser)`` - Hook to add global options to the parser
* ``make_client(instance)`` - Hook to create the client object

OSC enumerates the loaded plugins and loads commands from the entry points
defined for the API version:

::

    openstack.oscplugin.v1 =
        plugin_list = oscplugin.v1.plugin:ListPlugin
        plugin_show = oscplugin.v1.plugin:ShowPlugin

Note that OSC defines the group name as ``openstack.<api-name>.v<version>``
so the version should not contain the leading 'v' character.

This second step is identical to that performed for all but the Identity
client in OSC itself.  Identity is special due to the authentication
requirements.  This limits the ability to add additional auth modules to OSC.

Client
======

The current implementation of the ``tripleoclient`` Client class is an
empty placeholder.  This client object is not equired but OSC's ClientManager
will maintain it as required and is the interface point for other plugins to
access anything implemented by this plugin.
