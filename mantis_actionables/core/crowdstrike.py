import csv
import datetime
import ipaddr
import hashlib

from django.db.models import Q
from django.conf import settings

from dingos.models import IdentifierNameSpace
from mantis_actionables.models import Action, ImportInfo, SingletonObservable, SingletonObservableType,\
    SingletonObservableSubtype, Source, Status


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
    action.save()

    # get timestamp of last import (latest ImportInfo obj)
    latest_import_date = None
    latest_import_info = ImportInfo.objects\
        .filter(namespace=crowdstrike_namespace)\
        .filter(Q(type=ImportInfo.TYPE_CROWDSTRIKE_ACTOR) | Q(type=ImportInfo.TYPE_CROWDSTRIKE_REPORT))\
        .order_by('-create_timestamp')[0:1]
    if latest_import_info:
        latest_import_date = latest_import_info[0].create_timestamp.date()

    lines_added = 0
    lines_skipped = 0
    invalid_lines = []
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

        # create import infos for actors and reports and then add sources
        import_infos = []
        for actor in row['actor']:
            import_info = create_or_get_import_info(
                actor,
                ImportInfo.TYPE_CROWDSTRIKE_ACTOR,
                row['date'],
                crowdstrike_namespace,
                action
            )
            import_infos.append(import_info)

        for report in row['report']:
            import_info = create_or_get_import_info(
                report,
                ImportInfo.TYPE_CROWDSTRIKE_REPORT,
                row['date'],
                crowdstrike_namespace,
                action
            )
            import_infos.append(import_info)

        # create a generic Source relation between the SingletonObservable and each ImportInfo obj
        for import_info in import_infos:
            singleton_observable.sources.create(
                import_info=import_info,
                origin=Source.ORIGIN_VENDOR,
                processing=Source.PROCESSED_MANUALLY,
                tlp=Source.TLP_UNKOWN
            )

    return invalid_lines


def create_or_get_import_info(name, import_info_type, create_date, namespace, action):
            uid = hashlib.sha512(
                '%s_%s_%s_%s_%s' % (
                    import_info_type,
                    namespace.uri,
                    create_date.strftime('%x'),
                    name,
                    settings.SECRET_KEY,  # use as salt
                )
            )

            threatactor = ''
            if import_info_type == ImportInfo.TYPE_CROWDSTRIKE_ACTOR:
                threatactor = name

            import_info, _ = ImportInfo.objects.get_or_create(
                uid=uid,
                namespace=namespace,
                defaults={
                    'creating_action': action,
                    'create_timestamp': create_date,
                    'type': import_info_type,
                    'name': name,
                    'description': 'Autogenerated via crowdstrike csv import',
                    'related_threatactor': threatactor
                }
            )
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
            row['date'] = datetime.datetime.strptime(row['date'], '%Y-%m-%d').date()

            # types whitelist
            types_whitelist = [
                'binary_string',
                'domain',
                'email_address',
                'email_subject',
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
            }
            if row['type'] in map:
                row['type'] = map[row['type']]

            yield row, True