# simrs-md5

MD5 message-digest algorithm per RFC 1321.

Required by the Java Card `MessageDigest.ALG_MD5` API on JCOP20+ cards.
Provides a streaming `Md5` hasher and a one-shot `md5` function.

MD5 is cryptographically broken; included solely because Java Card 2.1.1
mandates it for legacy smart card applications.

`no_std`. No heap allocation.
