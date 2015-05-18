# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mantis_actionables', '0032_add_vSObs2Info_view'),
    ]

    operations = [
        migrations.CreateModel(
            name='vSObs2Info',
            fields=[
                ('id', models.PositiveIntegerField(serialize=False, primary_key=True)),
                ('type', models.CharField(max_length=255)),
                ('subtype', models.CharField(max_length=255)),
                ('value', models.CharField(max_length=2048)),
                ('actionable_tags_cache', models.TextField()),
                ('source_outdated', models.BooleanField()),
                ('source_tlp', models.SmallIntegerField()),
                ('source_timestamp', models.DateTimeField()),
                ('stix_entity_type', models.CharField(max_length=256)),
                ('stix_entity_essence', models.TextField()),
                ('top_level_iobject_identifier_ns_uri', models.CharField(max_length=256)),
                ('top_level_iobject_identifier_uid', models.SlugField(max_length=255)),
                ('top_level_iobject_identifier_latest_name', models.CharField(max_length=255)),
                ('iobject_identifier_ns_uri', models.CharField(max_length=256)),
                ('iobject_identifier_uid', models.SlugField(max_length=255)),
                ('iobject_identifier_latest_name', models.CharField(max_length=255)),
                ('import_info_ns_uri', models.CharField(max_length=256)),
                ('import_info_uid', models.SlugField(max_length=255)),
                ('import_info_name', models.CharField(max_length=255)),
                ('status_ts', models.DateTimeField()),
                ('status_most_permissive_tlp', models.SmallIntegerField()),
                ('status_max_confidence', models.SmallIntegerField()),
                ('status_best_processing', models.SmallIntegerField()),
                ('status_kill_chain_phases', models.TextField()),
                ('status_most_restrictive_tlp', models.SmallIntegerField()),
            ],
            options={
                'db_table': 'vsobs2info',
                'managed': False,
            },
            bases=(models.Model,),
        ),
    ]
