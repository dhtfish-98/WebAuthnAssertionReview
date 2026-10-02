from .common import *
from .crypto import *
import ipaddress,re
from urllib.parse import urlsplit

def serialized_origin(value):
    """Selected ASCII HTTPS origin profile; no URL path or normalization guesses."""
    value=string(value,1024)
    need(all(33<=ord(c)<=126 for c in value),"origin must be printable ASCII")
    try:
        origin=urlsplit(value);host=origin.hostname;port=origin.port
    except ValueError:raise ReviewError("invalid HTTPS origin") from None
    need(origin.scheme=='https' and host and origin.username is None and origin.password is None and not origin.path and not origin.query and not origin.fragment,"invalid HTTPS origin")
    if ':' in host:
        try:address=ipaddress.IPv6Address(host)
        except ValueError:raise ReviewError("invalid origin host") from None
        need('%' not in host,"scoped IP origin unsupported");authority='['+address.compressed+']'
    else:
        labels=host.removesuffix('.').split('.')
        need(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels),"invalid origin host")
        if labels[-1].isdigit() or re.fullmatch(r'0x[0-9a-f]+',labels[-1]):
            try:authority=str(ipaddress.IPv4Address(host))
            except ValueError:raise ReviewError("invalid origin IPv4 host") from None
        else:
            try:host.encode('ascii').decode('idna')
            except UnicodeError:raise ReviewError("invalid origin IDNA host") from None
            authority=host
    need(len(host)<=253,"origin host size limit")
    authority+=(':'+str(port)) if port is not None and port!=443 else ''
    need(value=='https://'+authority,"expected a canonical serialized HTTPS origin")
    return origin
def audit(d):
    fields(d,['credential','trusted_record','expected_challenge','expected_origin','expected_rp_id','require_user_verification'])
    c=obj(d['credential']);fields(c,['id','rawId','type','response']);need(c['type']=='public-key',"invalid credential type")
    record=obj(d['trusted_record']);fields(record,['credential_id','public_key','algorithm','sign_count'],['user_handle'])
    cid=b64(c['id'],True,1024);need(cid and cid==b64(c['rawId'],True,1024)==b64(record['credential_id'],True,1024),"credential identifier mismatch")
    r=obj(c['response']);fields(r,['clientDataJSON','authenticatorData','signature'],['userHandle'])
    client=b64(r['clientDataJSON'],True,65536);client_obj=load(client);fields(client_obj,['type','challenge','origin'],['crossOrigin'])
    need(client_obj['type']=='webauthn.get',"wrong ceremony type")
    expected=b64(d['expected_challenge'],True,1024);need(len(expected)>=16 and b64(client_obj['challenge'],True,1024)==expected,"challenge mismatch or too short")
    need(client_obj['origin']==string(d['expected_origin'],1024),"origin mismatch")
    origin=serialized_origin(d['expected_origin']);rp=string(d['expected_rp_id'],253);need(rp and (origin.hostname==rp or origin.hostname.endswith('.'+rp)),"invalid HTTPS relying party context")
    need(not boolean(client_obj.get('crossOrigin',False)),"cross-origin assertions unsupported")
    if 'userHandle' in r and r['userHandle'] is not None:
        need('user_handle' in record and b64(r['userHandle'],True,1024)==b64(record['user_handle'],True,1024),"user handle mismatch")
    auth=b64(r['authenticatorData'],True,4096);need(len(auth)==37,"only extension-free assertion authData supported")
    need(auth[:32]==hashlib.sha256(rp.encode()).digest(),"RP ID hash mismatch")
    flags=auth[32];need(flags&1 and not flags&0xE2,"user presence absent or unsupported flags")
    need(not flags&16 or flags&8,"invalid backup flag combination")
    uv=boolean(d['require_user_verification']);need(not uv or flags&4,"user verification required")
    old=integer(record['sign_count'],0,2**32-1);new=int.from_bytes(auth[33:],'big');need((old==new==0) or new>old,"signature counter did not increase")
    key=pubkey(record['public_key']);alg=record['algorithm'];need(alg in ('Ed25519','ES256'),"unsupported assertion algorithm")
    verify(key,b64(r['signature'],True,512),auth+hashlib.sha256(client).digest(),alg)
    return report(verified=True,credential_id_sha256=hashlib.sha256(cid).hexdigest(),new_sign_count=new,user_verified=bool(flags&4),backup_eligible=bool(flags&8),backed_up=bool(flags&16),state_updated=False)
