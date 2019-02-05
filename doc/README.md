# Generating Wazuh API Reference documentation

## Environment
Build vagrant envinroment using files available under `build_environment` directory.

## Generate documentation:

```shellsession
$ WAZUH_REPO=/home/vagrant/GitHub
$ cd $WAZUH_REPO/wazuh-api/doc
$ ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst
$ cd $WAZUH_REPO/wazuh-documentation/
$ make html
```

one-line command:
```shellsession
$ ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst && cd $WAZUH_REPO/wazuh-documentation/ && make html && cd -
```

Review **wazuh-documentation/source/user-manual/api/reference.rst**, specially *Example Response* section.
