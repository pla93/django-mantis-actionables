# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


sql_statement = """CREATE VIEW vsobs2info AS
SELECT
    mantis_actionables_singletonobservable.id AS id,
    mantis_actionables_singletonobservabletype.name AS type,
    mantis_actionables_singletonobservablesubtype.name AS subtype,
    mantis_actionables_singletonobservable.value AS value,
    mantis_actionables_singletonobservable.actionable_tags_cache AS actionable_tags_cache,

    mantis_actionables_source.id AS referenced_source_id,
    mantis_actionables_source.outdated AS source_outdated,
    mantis_actionables_source.tlp AS source_tlp,
    mantis_actionables_source.timestamp AS source_timestamp,
    mantis_actionables_source_related_stix_entities.stix_entity_id AS referenced_stix_entity_id,
    mantis_actionables_entitytype.name AS stix_entity_type,
    mantis_actionables_stix_entity.essence AS stix_entity_essence,

    mantis_actionables_source.top_level_iobject_id AS top_level_iobject_id,
    mantis_actionables_source.top_level_iobject_identifier_id AS top_level_iobject_identifier_id,
    dingos_identifiernamespace.uri AS top_level_iobject_identifier_ns_uri,
    dingos_identifier.uid AS top_level_iobject_identifier_uid,
    T11.name AS top_level_iobject_identifier_latest_name,

    mantis_actionables_source.iobject_id AS iobject_id,
    mantis_actionables_source.iobject_identifier_id AS iobject_identifier_id,
    T14.uri AS iobject_identifier_ns_uri,
    T13.uid AS iobject_identifier_uid,
    T15.name AS iobject_identifier_latest_name,

    mantis_actionables_source.import_info_id AS import_info_id,
    T17.uri AS import_info_ns_uri,
    mantis_actionables_importinfo.uid AS import_info_uid,
    mantis_actionables_importinfo.name AS import_info_name,

    mantis_actionables_status2x.timestamp AS status_ts,
    mantis_actionables_status2x.status_id AS status_id,
    mantis_actionables_status.most_permissive_tlp AS status_most_permissive_tlp,
    mantis_actionables_status.max_confidence AS status_max_confidence,
    mantis_actionables_status.best_processing AS status_best_processing,
    mantis_actionables_status.kill_chain_phases AS status_kill_chain_phases,
    mantis_actionables_status.most_restrictive_tlp AS status_most_restrictive_tlp
FROM
    mantis_actionables_singletonobservable
    INNER JOIN mantis_actionables_singletonobservabletype ON
    ( mantis_actionables_singletonobservable.type_id = mantis_actionables_singletonobservabletype.id )
    INNER JOIN mantis_actionables_singletonobservablesubtype ON
    ( mantis_actionables_singletonobservable.subtype_id = mantis_actionables_singletonobservablesubtype.id )
    LEFT OUTER JOIN mantis_actionables_source ON
    ( mantis_actionables_singletonobservable.id = mantis_actionables_source.object_id AND (mantis_actionables_source.content_type_id = 77))
    LEFT OUTER JOIN mantis_actionables_source_related_stix_entities ON
    ( mantis_actionables_source.id = mantis_actionables_source_related_stix_entities.source_id )
    LEFT OUTER JOIN mantis_actionables_stix_entity ON
    ( mantis_actionables_source_related_stix_entities.stix_entity_id = mantis_actionables_stix_entity.id )
    LEFT OUTER JOIN mantis_actionables_entitytype ON
    ( mantis_actionables_stix_entity.entity_type_id = mantis_actionables_entitytype.id )
    LEFT OUTER JOIN dingos_identifier ON
    ( mantis_actionables_source.top_level_iobject_identifier_id = dingos_identifier.id )
    LEFT OUTER JOIN dingos_identifiernamespace ON
    ( dingos_identifier.namespace_id = dingos_identifiernamespace.id )
    LEFT OUTER JOIN dingos_infoobject T11 ON
    ( dingos_identifier.latest_id = T11.id )
    LEFT OUTER JOIN dingos_identifier T13 ON
    ( mantis_actionables_source.iobject_identifier_id = T13.id )
    LEFT OUTER JOIN dingos_identifiernamespace T14 ON
    ( T13.namespace_id = T14.id )
    LEFT OUTER JOIN dingos_infoobject T15 ON
    ( T13.latest_id = T15.id )
    LEFT OUTER JOIN mantis_actionables_importinfo ON
    ( mantis_actionables_source.import_info_id = mantis_actionables_importinfo.id )
    LEFT OUTER JOIN dingos_identifiernamespace T17
    ON ( mantis_actionables_importinfo.namespace_id = T17.id )
    LEFT OUTER JOIN mantis_actionables_status2x ON
    ( mantis_actionables_singletonobservable.id = mantis_actionables_status2x.object_id AND (mantis_actionables_status2x.content_type_id = 77))
    LEFT OUTER JOIN mantis_actionables_status ON
    ( mantis_actionables_status2x.status_id = mantis_actionables_status.id )
    INNER JOIN mantis_actionables_status2x T20 ON
    ( mantis_actionables_singletonobservable.id = T20.object_id AND (T20.content_type_id = 77))
WHERE
    T20.active = True
"""

undo_statement = """DROP VIEW vsobs2info"""

class Migration(migrations.Migration):

    dependencies = [
        ('mantis_actionables', '0031_auto_20150513_1203'),
    ]

    operations = [
        migrations.RunSQL(
            sql_statement,
            undo_statement,
        ),
    ]