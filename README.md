Ansible AWS ElasticSearch Domain
=========

Ansible role for Elasticsearch (ES) Amazon Web Services (AWS). Creates/updates/deletes an AWS ES domain.

Role Variables
--------------

| parameter             | required | default | choices | comments |
| --------------------- | -------- | ------- | -------- |-------- |
| domain_name | yes | | | |
| es_version | yes | 6.4 | | |
| es_instance_type | yes | | | |
| es_instance_count | yes | 1 | | |
| dedicated_master_enabled | no | False | | |
| zone_awareness_enabled | no | False | | |
| zone_awareness_az_count | no | 2 | | |
| ebs_enabled | yes | | | |
| ebs_volume_type | yes | gp2 | | |
| ebs_volume_size | yes | 10Gb | | |
| ebs_iops | no | | | |
| access_policies | yes | | | |
| automated_snapshot_hour | no | 0 | | |
| vpc_deployment | no | | | |
| vpc_subnet_ids | no | | | |
| vpc_security_group_ids | no | false | | |
| encryption_at_rest_enabled | no | False | | |
| encryption_at_rest_kms_key_id | no | | | |
| advanced_options | no | {} | | |
| node_to_node_encryption_enabled | no | False | | Node to node encryption |
| advanced_options | no | {} | | |
| tags | no | {} | |   |
| wait | no | False | | |

Dependencies
------------

n/a

Example Playbook
----------------

Example invocation playbook

```
- hosts: localhost
  gather_facts: no
  roles:
    - role: aws_elasticsearch_domain
  vars:
    state: present
    domain_name: example-domain
    access_policy:
      Version: 2012-10-17
      Statement:
        - Effect: Allow
          Principal:
            AWS:
              - '{{ aws_account_id }}'
          Action:
            - 'es:*'
          Resource: "arn:aws:es:{{ aws_region }}:{{ aws_account_id }}:domain/{{ domain_name }}/*"
  tasks:
    - name: invoke the elasticsearch lib
      elasticsearch_domain:
        state: present
        domain_name: '{{ domain_name }}'
        access_policies: '{{ access_policy | to_nice_json }}'
        es_instance_type: m4.large.elasticsearch
        es_instance_count: 2
        encryption_at_rest_enabled: true
        encryption_at_rest_kms_key_id: '{{ some_key }}'
        automated_snapshot_hour: 2
        node_to_node_encryption_enabled: true
        zone_awareness_enabled: true
        zone_awareness_az_count: 2
        dedicated_master_enabled: true
        dedicated_master_instance_type: m4.large.elasticsearch
        dedicated_master_count: 3
        tags:
          Name: '{{ domain_name }}'
      register: es_domain
    - debug: msg="{{ es_domain.domain }}"
```

TODO
-------

- Add support for deeper nesting in the update sequences
- Add support for logging

Author Info
-------
David Heward

