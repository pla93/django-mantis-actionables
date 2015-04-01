# Copyright (c) Siemens AG, 2015
#
# This file is part of MANTIS.  MANTIS is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or(at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


import logging

import csv
import datetime
import ipaddr
import hashlib
import json
import pytz
from django.db.models import Q
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from mantis_actionables.status_management import updateStatus

from django.utils import timezone
from django.utils.dateparse import parse_datetime


from dingos.models import IdentifierNameSpace
from mantis_actionables.models import Action, ImportInfo, SingletonObservable, SingletonObservableType,\
    SingletonObservableSubtype, Source, Status, EntityType, STIX_Entity

logger = logging.getLogger(__name__)

CONTENT_TYPE_SINGLETON_OBSERVABLE = ContentType.objects.get_for_model(SingletonObservable)



def import_crowdstrike_csv(csv_file, printing=False):

    # get namespace for crowdstrike csv import
    crowdstrike_namespace, _ = IdentifierNameSpace.objects.get_or_create(
        uri='crowdstrike.com',
        defaults={
            'name': "Crowdstrike"
        }
    )

    # create a new action for this import
    action = Action(
        comment='Autogenerated via crowdstrike csv import on %s' % datetime.datetime.now().strftime('%c')
    )

    action, _ = Action.objects.get_or_create(comment='Autogenerated via crowdstrike csv import on %s' % datetime.datetime.now().strftime('%c'))


    # get timestamp of last import (latest ImportInfo obj)
    latest_import_date = None
    latest_import_info = ImportInfo.objects\
        .filter(namespace=crowdstrike_namespace)\
        .filter(Q(type=ImportInfo.TYPE_BULK_IMPORT))\
        .order_by('-create_timestamp')[0:1]
    if latest_import_info:
        latest_import_date = latest_import_info[0].create_timestamp#.date()

    lines_added = 0
    lines_skipped = 0
    invalid_lines = []

    actor2entity_map = {}
    ta_entity_type, created = EntityType.cached_objects.get_or_create(name="ThreatActor")

    generic_entity_type, created = EntityType.cached_objects.get_or_create(name="Generic")

    domaintype2entity_map = {}



    for row, valid_row in read_crowdstrike_csv_generator(csv_file, printing):
        # invalid lines will be returned at the end, a line is invalid if the type is not in the whitelist
        if not valid_row:
            invalid_lines.append(row)
            continue

        # skip rows older then latest_import
        if latest_import_date and row['date'] <= latest_import_date:
            lines_skipped += 1

            continue

        # type and subtype are just given as strings (empty string if not subtype is given)
        type, _ = SingletonObservableType.cached_objects.get_or_create(
            name=row['type']
        )
        subtype, _ = SingletonObservableSubtype.cached_objects.get_or_create(
            name=row['subtype']
        )

        # create singleton observable
        singleton_observable, created = SingletonObservable.objects.get_or_create(
            type=type,
            subtype=subtype,
            value=row['indicator']
        )


        # if the singleton observable is new, add a status
        if created:
            lines_added += 1

            status = Status(
                priority=Status.PRIORITY_UNCERTAIN
            )
            status.save()

            singleton_observable.status_thru.create(
                action=action,
                status=status
            )

        dt_entity = None
        related_entities = []

        if row.get('domaintype'):
            domaintype = row.get('domaintype')
            if not domaintype in ['None','Unknown']:
                if not domaintype in domaintype2entity_map:
                    dt_entity, created = STIX_Entity.objects.get_or_create(iobject_identifier_id=None,
                                                                       non_iobject_identifier='{crowdstrike.com}DomainType-%s' % domaintype,
                                                                       defaults={'essence': json.dumps({'domaintype':domaintype}),
                                                                       'entity_type':generic_entity_type})
                    domaintype2entity_map[domaintype] = dt_entity


                dt_entity = domaintype2entity_map[domaintype]

                related_entities.append(domaintype2entity_map[domaintype])


        # create import infos for actors and reports and then add sources
        import_infos = []



        for actor in row['actor']:


            if not actor in actor2entity_map:
                ta_entity, created = STIX_Entity.objects.get_or_create(iobject_identifier_id=None,
                                                                       non_iobject_identifier='{crowdstrike.com}ThreatActor-%s' % actor,
                                                                       defaults={'essence': json.dumps({'identities':actor}),
                                                                       'entity_type':ta_entity_type})
                actor2entity_map[actor] = ta_entity

            ta_entity = actor2entity_map[actor]

            related_entities.append(ta_entity)


            import_info = create_or_get_import_info(
                actor,
                ImportInfo.TYPE_BULK_IMPORT,
                row['date'],
                crowdstrike_namespace,
                action,
                report_name = 'Crowdstrike indicators of %s associated with Threat Actor "%s"' % (row['date'],actor),
            )


            import_info.related_stix_entities.add(ta_entity)


            if dt_entity:
                import_info.related_stix_entities.add(dt_entity)

            import_infos.append(import_info)


        for report in row['report']:
            import_info = create_or_get_import_info(
                report,
                ImportInfo.TYPE_BULK_IMPORT,
                row['date'],
                crowdstrike_namespace,
                action,
                report_name = 'Crowdstrike indicators of %s referencing report "%s"' % (row['date'],report)
            )
            import_infos.append(import_info)

            if dt_entity:
                import_info.related_stix_entities.add(dt_entity)



        # create a generic Source relation between the SingletonObservable and each ImportInfo obj
        for import_info in import_infos:
            source, source_created = Source.objects.get_or_create(
                                                       object_id=singleton_observable.id,
                                                       content_type=CONTENT_TYPE_SINGLETON_OBSERVABLE,
                                                       import_info = import_info,
                                                       defaults = {
                                                          'processing': Source.PROCESSED_MANUALLY,
                                                          'origin': Source.ORIGIN_PARTNER,
                                                          'tlp': Source.TLP_AMBER
                                                       }

                                                    )
            if related_entities:
                source.related_stix_entities.add(*related_entities)

            singleton_observable.update_status(update_function=updateStatus,
                                               action=action,
                                               user=None,
                                               source_obj = source,
                                               related_entities = related_entities,
                                               import_info_obj = import_info)

            if not source_created:
                logger.debug("Found existing source object")
            else:
                logger.debug("Created new source object")


    return invalid_lines


def create_or_get_import_info(referenced_name, import_info_type, create_date, namespace, action,entities=[],report_name=None):

    uid = hashlib.sha256(
        '%s_%s_%s_%s_%s' % (
            import_info_type,
            namespace.uri,
            create_date.strftime('%x'),
            referenced_name,
            settings.SECRET_KEY,  # use as salt
        )
    ).hexdigest()


    import_info, created = ImportInfo.objects.get_or_create(
        uid=uid,
        namespace=namespace,
        defaults={
            'creating_action' : action,
            'create_timestamp': create_date,
            'type': import_info_type,
            'name': report_name,
            'description': 'Autogenerated via crowdstrike csv import',
        }
    )


    if created:
        import_info.related_stix_entities.add(*entities)
    return import_info


def read_crowdstrike_csv_generator(csv_file, printing):
    lines_total = sum(1 for line in open(csv_file))

    with open(csv_file) as handle:
        reader = csv.DictReader(handle)
        lines_processed = 0
        procent = -1
        for row in reader:
            """
            csv file has the following columns:
            date - string (d.m.Y)
            indicator - string
            type - string
            actor - list of actors, seperated by |
            report - list of reports, seperated by |
            domaintype - string
            """


            # print progress in procent
            current_procent = int(round(float(lines_processed) / lines_total * 100))
            if procent != current_procent:
                procent = current_procent
                if printing:
                    print '%s%% processed (%i lines)' % (procent, lines_processed)
            lines_processed += 1

            # split actor string and filter "empty" values
            actor_empty_values = ['unknown', 'none', ]
            actors = []
            for actor in row['actor'].split('|'):
                if actor.strip() and actor.lower() not in actor_empty_values:
                    actors.append(actor)
            row['actor'] = actors

            # split report string and filter "empty" values
            report_empty_values = ['unknown', 'none', ]
            reports = []
            for report in row['report'].split('|'):
                if report.strip() and report.lower() not in report_empty_values:
                    reports.append(report)
            row['report'] = reports

            # skip entry if there is no actor and no report
            if not row['actor'] and not row['report']:
                continue

            # change date string to a Date obj

            naive = datetime.datetime.strptime(row['date'], '%Y-%m-%d')#.date()


            aware = naive.replace(tzinfo=pytz.timezone('Etc/GMT+0'))



            row['date'] = aware


            types_whitelist = [
                'binary_string',
                'domain',
                'email_address',
                'email_subject',
                'event_name',
                'file_mapping',
                'file_name',
                'file_path',
                'hash_md5',
                'hash_sha1',
                'hash_sha256',
                'ip_address',
                'ip_address_block',
                'mutex_name',
                'password',
                'persona_name',
                'registry',
                'service_name',
                'url',
                'user_agent',
                'username',
                'x509_serial',
                'x509_subject',
            ]

            row['subtype'] = ''

            # row is invalid because type is unkown
            if not row['type'] in types_whitelist:
                yield row, False
                continue

            # types which may have a subtype in mantis
            if row['type'] == 'hash_md5':
                row['type'] = 'Hash'
                row['subtype'] = 'MD5'
            if row['type'] == 'hash_sha1':
                row['type'] = 'Hash'
                row['subtype'] = 'SHA1'
            if row['type'] == 'hash_sha256':
                row['type'] = 'Hash'
                row['subtype'] = 'SHA256'

            if row['type'] == 'registry':
                row['type'] = 'Registry'
                row['subtype'] = 'Key'

            if row['type'] == 'ip_address':
                row['type'] = 'IP'
                try:
                    ip = ipaddr.IPAddress(row['indicator'])
                    if ip.version == 4 or ip.version == 6:
                        row['subtype'] = 'v%s' % ip.version
                except:
                    pass
            if row['type'] == 'ip_address_block':
                row['type'] = 'IP_Block'
                try:
                    ip_block = ipaddr.IPNetwork(row['indicator'])
                    if ip_block.version == 4 or ip_block.version == 6:
                        row['subtype'] = 'v%s' % ip_block.version
                except:
                    pass

            if row['type'] == 'x509_serial':
                row['type'] = 'x509'
                row['subtype'] = 'Serial'
            if row['type'] == 'x509_subject':
                row['type'] = 'x509'
                row['subtype'] = 'CN'

            # simple renaming of types without subtypes
            map = {
                'file_name': 'Filename',
                'file_path': 'Filepath',
                'domain': 'FQDN',
                'url': 'URL',
                'email_address': 'Email_Address',
                'email_subject': 'Email_Subject',
                'user_agent': 'User_Agent',
                'binary_string': 'Binary_String',
                'persona_name': 'Persona_Name',
                'event_name': 'Event_Name',
                'password': 'Password',
                'file_mapping': 'File_Mapping',
                'mutex_name' : 'Mutex_Name',
                'service_name': 'Service_Name',
                'username': 'Username',

            }


            if row['type'] in map:
                row['type'] = map[row['type']]

            yield row, True