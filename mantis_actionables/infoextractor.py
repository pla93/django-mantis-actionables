#!/usr/bin/python
# -*- coding: utf-8 -*-

import os, re
from iptools import IpRangeList
from urlparse import urlparse

class TokenProcessor:
    parent = None
    def __init__(self, parent):
        self.parent = parent

    def process_token(self, token):
        """Preprocesses the token and possibly yields new tokens. E.g. an URI may result
        in a domain part, a file part etc.

        """
        yield None

    def is_of_type(self, token):
        """Should return True if token is of self.infotype

        """
        return False


class InfoExtractor:
    """Class which executes plugged in classes to extract information from a passed
    text

    """

    text = None
    text_tokenized = None
    separator = None
    plugins = None
    result_dict = None
    replacements = {
        '[.]': '.',
        'hxxp://': 'http://',
        'hxxps://': 'https://',
        'hxxxs://': 'https://',
        '(at)': '@',
        '[at]': '@'
    }
    extract_enclosed = ['""', '\'\'', '()', '[]', u'‘’', '{}', u'`´', u'“”']
    strip_chars = u'"\'()[]‘’{}`´,.“”'
    
    def __init__(self, text, **kwargs):
        self.text = text
        if 'separator' in kwargs.keys():
            sep = kwargs.get('separator')
            if type(sep) == str:
                self.separator = sep
        self.result_dict = {}
        self.text_tokenized = {}
        self.plugins = []


    def add_processor(self, cls):
        self.plugins.append(cls(self))

    def add_result_row(self, token, infotype, original_token):
        try: # Check if exists
            self.result_dict[(token, infotype, original_token)]
        except: # Does not exist in search array, add.
            self.result_dict[(token, infotype, original_token)] = True

    def token_generator(self):
        def _ad(d, k, v):
            _nv = d.get(k, list())
            if not v in _nv:
                _nv.append(v)
            d[k] = _nv
            
        # Init the tokens. Do some preprocessing of replacing common stuff like
        # hxxp:// or like removing brackets or parenthesis.
        if len(self.text_tokenized) == 0:
            for token in self.text.split(self.separator):
                _ad(self.text_tokenized, token, token)

                # Replacements
                t_rep = token
                for rep_source, rep_target in self.replacements.iteritems():
                    if t_rep.count(rep_source) > 0:
                        t_rep = t_rep.replace(rep_source, rep_target)
                if t_rep != token:
                    _ad(self.text_tokenized, t_rep, token)

                # Extraction of enclosed strings
                for enc_pair in self.extract_enclosed:
                    left_pos = token.find(enc_pair[0])
                    right_pos = token.rfind(enc_pair[1])
                    if left_pos!=-1 and right_pos!=-1:
                        _ad(self.text_tokenized, token[left_pos+1:right_pos], token)

                # Strip characters from string
                _ad(self.text_tokenized, token.strip(self.strip_chars), token)


                
        for token, original_token_list in self.text_tokenized.iteritems():
            original_token = ", ".join(original_token_list)
            yield (token, original_token)
            for pi in self.plugins:
                for new_token in pi.process_token(token):
                    if new_token is not None and (new_token != token):
                        yield (new_token, original_token)


    def process(self):
        for token, original_token in self.token_generator():
            for pi in self.plugins:
                infotype = pi.infotype
                if pi.is_of_type(token):
                    # We got a result. Check for doubles.
                    self.add_result_row(token, infotype, original_token)
                    
                    
    def result(self):
        self.process()
        return self.result_dict.keys()

    
class ProcessorMD5(TokenProcessor):
    infotype = 'Hash'
    def is_of_type(self, token):
        if re.search(r"^([a-fA-F\d]{32})", token):
            return True
        return False


class ProcessorIP(TokenProcessor):
    infotype = 'IP'

    def replace_ph(self, token):
        return token.lower().replace('.x', '.0').replace('.y', '.0').replace('.z', '.0')
    
    def process_token(self, token):
        ni = self.replace_ph(token)

        # Skip if we dont fulfil criteria (eg. for inputs like 0, 1, 2 and so on)
        if not self.is_of_type(ni):
            return
        
        if ni != token:
            yield ni

        if ni.count(':') == 1: # is there a port specified?
            ni_noport = ni[:ni.find(':')]
            if self.is_of_type(ni_noport):
                yield ni_noport
            
        try:
            r = IpRangeList(ni)
            if not r.__len__() > 512:
                for ip in r.__iter__():
                    # Yield every ip in the range if we have not more than 512
                    yield ip
        except:
            pass
        
            
    def is_of_type(self, token):
        # If we have at least 2 dots in the string we try to parse IPs. This
        # eliminates versions (e.g. 1.0) and single numbers (e.g. 8 -> 8.0.0.0)
        # Also after replacing .x .y .z to .0 we should not have 
        if token.count('.') > 2 and token.count('.') <= 4 and not re.search(r"[a-z]", self.replace_ph(token)):
            return True
        return False


class ProcessorEmail(TokenProcessor):
    infotype = 'Email_Address'
    def is_of_type(self, token):
        # TODO: make better email matching
        if re.match(r"^[a-zA-Z0-9._]+\@[a-zA-Z0-9._]+\.[a-zA-Z]{3,}$", token)!=None:
            return True
        return False


class ProcessorURI(TokenProcessor):
    infotype = 'URL'

    proto_strings = ('http://', 'https://', 'ftp://', 'ftps://', 'smtp://', 'smtps://', 'pop://', 'pops://', 'imap://', 'imaps://', 'file://', '/')

    def process_token(self, token):
        if self.is_of_type(token):
            o = urlparse(token)
            if o.netloc!='':
                yield o.netloc
            if o.path != '' and (o.path != '/' or o.path != '\\'):
                yield o.path
            fname = os.path.basename(o.path)
            if fname:
                yield fname
    
    def is_of_type(self, token):
        for p in self.proto_strings:
            if token.lower().startswith(p) and not token=='/':
                return True


class ProcessorDomain(TokenProcessor):
    infotype = 'Domain'
    tlds = ('abogado', 'ac', 'academy', 'accountants', 'active', 'actor', 'ad', 'ae', 'aero', 'af', 'ag', 'agency', 'ai', 'airforce', 'al', 'allfinanz', 'alsace', 'am', 'an', 'android', 'ao', 'aq', 'ar', 'archi', 'army', 'arpa', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'auction', 'audio', 'autos', 'aw', 'ax', 'axa', 'az', 'ba', 'band', 'bar', 'bargains', 'bayern', 'bb', 'bd', 'be', 'beer', 'berlin', 'best', 'bf', 'bg', 'bh', 'bi', 'bid', 'bike', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'bloomberg', 'blue', 'bm', 'bmw', 'bn', 'bnpparibas', 'bo', 'boo', 'boutique', 'br', 'brussels', 'bs', 'bt', 'budapest', 'build', 'builders', 'business', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'cal', 'camera', 'camp', 'cancerresearch', 'capetown', 'capital', 'caravan', 'cards', 'care', 'career', 'careers', 'casa', 'cash', 'cat', 'catering', 'cc', 'cd', 'center', 'ceo', 'cern', 'cf', 'cg', 'ch', 'channel', 'cheap', 'christmas', 'chrome', 'church', 'ci', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'click', 'clinic', 'clothing', 'club', 'cm', 'cn', 'co', 'codes', 'coffee', 'college', 'cologne', 'com', 'community', 'company', 'computer', 'condos', 'construction', 'consulting', 'contractors', 'cooking', 'cool', 'coop', 'country', 'cr', 'credit', 'creditcard', 'cricket', 'crs', 'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cz', 'dad', 'dance', 'dating', 'day', 'de', 'deals', 'degree', 'delivery', 'democrat', 'dental', 'dentist', 'desi', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount', 'dj', 'dk', 'dm', 'dnp', 'do', 'domains', 'durban', 'dvag', 'dz', 'eat', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'equipment', 'er', 'es', 'esq', 'estate', 'et', 'eu', 'eus', 'events', 'exchange', 'expert', 'exposed', 'fail', 'farm', 'feedback', 'fi', 'finance', 'financial', 'firmdale', 'fish', 'fishing', 'fitness', 'fj', 'fk', 'flights', 'florist', 'flsmidth', 'fly', 'fm', 'fo', 'foo', 'forsale', 'foundation', 'fr', 'frl', 'frogans', 'fund', 'furniture', 'futbol', 'ga', 'gal', 'gallery', 'gb', 'gbiz', 'gd', 'ge', 'gent', 'gf', 'gg', 'gh', 'gi', 'gift', 'gifts', 'gives', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmo', 'gmx', 'gn', 'google', 'gop', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gratis', 'green', 'gripe', 'gs', 'gt', 'gu', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hamburg', 'haus', 'healthcare', 'help', 'here', 'hiphop', 'hiv', 'hk', 'hm', 'hn', 'holdings', 'holiday', 'homes', 'horse', 'host', 'hosting', 'house', 'how', 'hr', 'ht', 'hu', 'ibm', 'id', 'ie', 'il', 'im', 'immo', 'immobilien', 'in', 'industries', 'info', 'ing', 'ink', 'institute', 'insure', 'int', 'international', 'investments', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jetzt', 'jm', 'jo', 'jobs', 'joburg', 'jp', 'juegos', 'kaufen', 'ke', 'kg', 'kh', 'ki', 'kim', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'kp', 'kr', 'krd', 'kred', 'kw', 'ky', 'kz', 'la', 'lacaixa', 'land', 'lawyer', 'lb', 'lc', 'lds', 'lease', 'lgbt', 'li', 'life', 'lighting', 'limited', 'limo', 'link', 'lk', 'loans', 'london', 'lotto', 'lr', 'ls', 'lt', 'ltda', 'lu', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid', 'maison', 'management', 'mango', 'market', 'marketing', 'mc', 'md', 'me', 'media', 'meet', 'melbourne', 'meme', 'menu', 'mg', 'mh', 'miami', 'mil', 'mini', 'mk', 'ml', 'mm', 'mn', 'mo', 'mobi', 'moda', 'moe', 'monash', 'mormon', 'mortgage', 'moscow', 'motorcycles', 'mov', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nagoya', 'name', 'navy', 'nc', 'ne', 'net', 'network', 'neustar', 'new', 'nexus', 'nf', 'ng', 'ngo', 'nhk', 'ni', 'ninja', 'nl', 'no', 'np', 'nr', 'nra', 'nrw', 'nu', 'nyc', 'nz', 'okinawa', 'om', 'ong', 'onl', 'ooo', 'org', 'organic', 'otsuka', 'ovh', 'pa', 'paris', 'partners', 'parts', 'party', 'pe', 'pf', 'pg', 'ph', 'pharmacy', 'photo', 'photography', 'photos', 'physio', 'pics', 'pictures', 'pink', 'pizza', 'pk', 'pl', 'place', 'plumbing', 'pm', 'pn', 'pohl', 'poker', 'post', 'pr', 'praxi', 'press', 'pro', 'prod', 'productions', 'prof', 'properties', 'property', 'ps', 'pt', 'pub', 'pw', 'py', 'qa', 'qpon', 'quebec', 're', 'realtor', 'recipes', 'red', 'rehab', 'reise', 'reisen', 'reit', 'ren', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'reviews', 'rich', 'rio', 'rip', 'ro', 'rocks', 'rodeo', 'rs', 'rsvp', 'ru', 'ruhr', 'rw', 'ryukyu', 'sa', 'saarland', 'sarl', 'sb', 'sc', 'sca', 'scb', 'schmidt', 'schule', 'science', 'scot', 'sd', 'se', 'services', 'sexy', 'sg', 'sh', 'shiksha', 'shoes', 'si', 'singles', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'social', 'software', 'sohu', 'solar', 'solutions', 'soy', 'space', 'spiegel', 'sr', 'st', 'su', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'sx', 'sy', 'sydney', 'systems', 'sz', 'taipei', 'tatar', 'tattoo', 'tax', 'tc', 'td', 'technology', 'tel', 'tf', 'tg', 'th', 'tienda', 'tips', 'tirol', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'top', 'town', 'toys', 'tp', 'tr', 'trade', 'training', 'travel', 'tt', 'tui', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'university', 'uno', 'uol', 'us', 'uy', 'uz', 'va', 'vacations', 'vc', 've', 'vegas', 'ventures', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'villas', 'vision', 'vlaanderen', 'vn', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'vu', 'wales', 'wang', 'watch', 'webcam', 'website', 'wed', 'wedding', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'wme', 'work', 'works', 'world', 'ws', 'wtc', 'wtf', 'xn--1qqw23a', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c', 'xn--45q11c', 'xn--4gbrim', 'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--c1avg', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--flw351e', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--gecrj9c', 'xn--h2brj9c', 'xn--i1b6b1a6a2e', 'xn--io0a7i', 'xn--j1amh', 'xn--j6w193g', 'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd', 'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar', 'xn--mgbx4cd0ab', 'xn--ngbc5azd', 'xn--node', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--p1acf', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--qcka1pmc', 'xn--rhqv96g', 'xn--s9brj9c', 'xn--ses554g', 'xn--unup4y', 'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yandex', 'ye', 'yoga', 'yokohama', 'youtube', 'yt', 'za', 'zip', 'zm', 'zone', 'zw')

    def is_of_type(self, token):
        for tld in self.tlds:
            _tl = token.lower()
            if _tl.endswith('.' + tld) and _tl.count('@') == 0:
                return True
        return False


class ProcessorFile(TokenProcessor):
    infotype = 'Filename'
    def process_token(self, token):
        base_token = os.path.basename(token.replace('\\', '/'))
        if base_token != token:
            yield base_token
            
    def is_of_type(self, token):
        # File is currently the most unreliable detection. We might want to
        # accept anything to search for every word. ...or we expect at least one
        # dot and require the filename not to start with a *slash (like in URIs)
        # and not end with a dot. We also Exclude URIs from the ProcessorURI
        if token.count('.') > 0 and not token.endswith('.') and not token.startswith('/') and not token.startswith('\\'):
            proc_uri = ProcessorURI(self.parent)
            proc_ip = ProcessorIP(self.parent)
            if not proc_uri.is_of_type(token) and not proc_ip.is_of_type(token):
                return True
        return False
