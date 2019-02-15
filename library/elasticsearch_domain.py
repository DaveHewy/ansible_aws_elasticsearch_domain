#!/usr/bin/python
#
# Copyright (c) 2017 Ansible Project
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---

"""

try:
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import time
import json
from ansible.module_utils._text import to_native
from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import boto3_conn, compare_policies, ec2_argument_spec, get_aws_connection_info


def _create_elasticsearch_domain(module, client):
    """Create an elasticsearch domain

    Arguments:
        module {[type]} -- [description]
        client {[type]} -- [description]
    """
    domain_name = module.params.get('domain_name')
    es_version = module.params.get('es_version')
    es_instance_type = module.params.get('es_instance_type')
    es_instance_count = module.params.get('es_instance_count')

    dedicated_master_enabled = module.params.get('dedicated_master_enabled')
    dedicated_master_count = module.params.get('dedicated_master_count')
    dedicated_master_instance_type = module.params.get('dedicated_master_instance_type')

    zone_awareness_enabled = module.params.get('zone_awareness_enabled')
    zone_awareness_az_count = module.params.get('zone_awareness_az_count')

    ebs_enabled = module.params.get('ebs_enabled')
    ebs_volume_type = module.params.get('ebs_volume_type')
    ebs_volume_size = module.params.get('ebs_volume_size')
    ebs_iops = module.params.get('ebs_iops')

    access_policies = module.params.get('access_policies')

    automated_snapshot_hour = module.params.get('automated_snapshot_hour')

    encryption_at_rest_enabled = module.params.get('encryption_at_rest_enabled')
    encryption_at_rest_kms_key_id = module.params.get('encryption_at_rest_kms_key_id')

    node_to_node_encryption_enabled = module.params.get('node_to_node_encryption_enabled')
    advanced_options = module.params.get('advanced_options')

    # VPC options
    vpc_deployment = module.params.get('vpc_deployment')
    vpc_subnet_ids = module.params.get('vpc_subnet_ids')
    vpc_security_group_ids = module.params.get('vpc_security_group_ids')

    es_config = {
        'DomainName': domain_name,
        'ElasticsearchVersion': es_version,
        'ElasticsearchClusterConfig': {
            'InstanceType': es_instance_type,
            'InstanceCount': es_instance_count,
            'DedicatedMasterEnabled': dedicated_master_enabled,
            'ZoneAwarenessEnabled': zone_awareness_enabled
        },
        'EBSOptions': {
            'EBSEnabled': ebs_enabled,
            'VolumeType': ebs_volume_type,
            'VolumeSize': ebs_volume_size
        },
        'SnapshotOptions': {
            'AutomatedSnapshotStartHour': automated_snapshot_hour
        },
        'AccessPolicies': access_policies,
        'AdvancedOptions': advanced_options
    }

    # If encryption is enabled, configure it
    if encryption_at_rest_enabled:
        es_config.update(EncryptionAtRestOptions={
            'Enabled': True,
            'KmsKeyId': encryption_at_rest_kms_key_id
        })

    # if node to node encryption, configure it
    if node_to_node_encryption_enabled:
        es_config.update(NodeToNodeEncryptionOptions={
            'Enabled': True
        })

    # If io1, then specificy the iops value
    if ebs_volume_type == 'io1':
        es_config['EBSOptions'].update(
            Iops=ebs_iops
        )

    # If dedicated master is passed
    if dedicated_master_enabled:
        if dedicated_master_instance_type:
            es_config['ElasticsearchClusterConfig'].update(
                DedicatedMasterType=dedicated_master_instance_type
            )
        if dedicated_master_count:
            es_config['ElasticsearchClusterConfig'].update(
                DedicatedMasterCount=dedicated_master_count
            )

    # If zone awareness enabled extend the ElasticsearchClusterConfig key
    if zone_awareness_enabled:
        es_config['ElasticsearchClusterConfig'].update(
            ZoneAwarenessConfig={
                'AvailabilityZoneCount': zone_awareness_az_count
            }
        )

    # If vpc_deployment of ES
    if vpc_deployment:
        es_config.update(VPCOptions={
            'SubnetIds': vpc_subnet_ids,
            'SecurityGroupIds': vpc_security_group_ids
        })

    # Attempt to create the elasticsearch cluster
    try:
        response = client.create_elasticsearch_domain(**es_config)
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg='Unable to create ElasticSearch domain')
    return response


def ensure_updated(module, client):
    """`

    [description]
    """
    return False


def is_update_required(module, es_domain):
    """[summary]

    [description]

    Arguments:
        module {[type]} -- [description]
        client {[type]} -- [description]
    """
    return False


def is_present(module, client):
    """Function to determine whether or not the elasticseach is present

    Arguments:
        module {[type]} -- [description]
        client {[type]} -- [description]
    """
    domain_name = module.params.get('domain_name')
    try:
        response = client.describe_elasticsearch_domain(
            DomainName=domain_name
        )
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        else:
            module.fail_json_aws(e, msg='Unexpected error {0}'.format(to_native(e)))
    return response


def ensure_deleted(module, client):
    """Deletes an elasticsearch domain by DomainName

    Arguments:
        module {[type]} -- [description]
        client {[type]} -- [description]
    """
    domain_name = module.params.get('domain_name')
    try:
        client.delete_elasticsearch_domain(DomainName=domain_name)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        else:
            module.fail_json_aws(e, msg='Unexpected error {0}'.format(to_native(e)))
    return True


def ensure_created(module, client):
    """Ensures elasticsearch domain is created

    Arguments:
        module {[type]} -- [description]
        client {[type]} -- [description]
    """
    es_domain = is_present(module, client)
    if es_domain:
        changed = False
    else:
        es_domain = _create_elasticsearch_domain(module, client)
        changed = True
        return changed, es_domain


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        domain_name=dict(required=True, type='str'),
        es_version=dict(type='str', default='6.4'),
        es_instance_type=dict(type='str'),
        es_instance_count=dict(type='int', default=1),

        dedicated_master_enabled=dict(type='bool', default=False),
        dedicated_master_count=dict(type='int', default=1),
        dedicated_master_instance_type=dict(type='str'), # required if

        zone_awareness_enabled=dict(type='bool', default=False),
        zone_awareness_az_count=dict(type='int', default=2),

        ebs_enabled=dict(type='bool', default=True),
        ebs_volume_type=dict(type='str', choices=['standard', 'gp2', 'io1'], default='gp2'),
        ebs_volume_size=dict(type='int', default=10),
        ebs_iops=dict(type='int'),
        access_policies=dict(type='json', required=True),
        automated_snapshot_hour=dict(type='int', default=0),


        vpc_deployment=dict(type='bool', default=False),
        vpc_subnet_ids=dict(type='list'),
        vpc_security_group_ids=dict(type='list'),
        # un-supported params atm
        # cognito_options=dict(type='dict'),

        encryption_at_rest_enabled=dict(type='bool', default=False),
        encryption_at_rest_kms_key_id=dict(type='str'),

        node_to_node_encryption_enabled=dict(type='bool', default=False),
        advanced_options=dict(type='dict', default={}),
        log_publishing_options=dict(type='dict'),
        tags=dict(type='dict'),
        wait=dict(type='bool')
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
    )

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    client = boto3_conn(
        module,
        conn_type='client',
        resource='es',
        region=region,
        endpoint=ec2_url,
        **aws_connect_kwargs)

    tags = module.params.get('tags')
    state = module.params.get('state')
    if state == 'present':
        changed, es_domain = ensure_created(module, client)
        update_required = is_update_required(module, es_domain)

        if update_required:
            es_domain = ensure_updated(module, client)

        # Create tags
        if tags:
            tag_list = []
            for tag_key, tag_value in tags.items():
                tag_list.append({'Key': tag_key, 'Value': tag_value})

            client.add_tags(ARN=es_domain['DomainStatus']['ARN'], TagList=tag_list)

        # if wait is defined
        if module.params.get('wait'):
            while not es_domain['DomainStatus'].get('Endpoint'):
                time.sleep(10)
                es_domain = is_present(module, client)

    elif state == 'absent':
        changed = ensure_deleted(module, client)
        es_domain = {}

    module.exit_json(changed=changed, domain=es_domain)


if __name__ == '__main__':
    main()
