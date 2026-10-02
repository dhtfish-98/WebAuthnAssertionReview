import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from webauthn_assertion_review import audit
from webauthn_assertion_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','webauthn_assertion_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class WebAuthnTests(unittest.TestCase):
    def setUp(self):
        self.k=ed25519.Ed25519PrivateKey.generate();cid=b'synthetic credential';challenge=b'0123456789abcdefghijklmnopqrstuv';client=json.dumps({'type':'webauthn.get','challenge':url(challenge),'origin':'https://example.invalid','crossOrigin':False},separators=(',',':')).encode();auth=hashlib.sha256(b'example.invalid').digest()+b'\x05'+(2).to_bytes(4,'big');sig=self.k.sign(auth+hashlib.sha256(client).digest())
        self.d={'credential':{'id':url(cid),'rawId':url(cid),'type':'public-key','response':{'clientDataJSON':url(client),'authenticatorData':url(auth),'signature':url(sig)}},'trusted_record':{'credential_id':url(cid),'public_key':pemkey(self.k),'algorithm':'Ed25519','sign_count':1},'expected_challenge':url(challenge),'expected_origin':'https://example.invalid','expected_rp_id':'example.invalid','require_user_verification':True}
    def test_valid(self):self.assertTrue(audit(self.d)['verified']);save_example(self.d)
    def test_challenge_origin_replay_signature_flags(self):
        mutations=[lambda d:d.update(expected_challenge=url(bytes(32))),lambda d:d.update(expected_origin='https://other.invalid'),lambda d:d['trusted_record'].update(sign_count=2),lambda d:d['credential']['response'].update(signature=url(bytes(64))),lambda d:d['credential']['response'].update(authenticatorData=url(bytes(37)))]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d)
            with self.assertRaises(ReviewError):audit(d)
    def test_es256_and_unsupported_extension(self):
        k=ec.generate_private_key(ec.SECP256R1());r=self.d['credential']['response'];auth=base64.urlsafe_b64decode(r['authenticatorData']+'='*((-len(r['authenticatorData']))%4));client=base64.urlsafe_b64decode(r['clientDataJSON']+'='*((-len(r['clientDataJSON']))%4));r['signature']=url(k.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256())));self.d['trusted_record'].update(public_key=pemkey(k),algorithm='ES256');self.assertTrue(audit(self.d)['verified']);r['authenticatorData']=url(auth+b'\xa0')
        with self.assertRaises(ReviewError):audit(self.d)

if __name__=="__main__":unittest.main()
