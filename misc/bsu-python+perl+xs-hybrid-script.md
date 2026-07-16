# Why adding a perl XS for Zeroing 

Zero Material improvement with the right mix of perl + python ...

This a much stronger architecture than pure Python as our objective is **controlled secret lifetime and explicit zeroization**.

A Perl + Python hybrid with an XS layer can do something Python alone cannot: **hold the sensitive buffer in native memory and explicitly wipe it**.


```
             random sources
                  |
                  v
            Perl generator
                  |
        (native scalar / malloc buffer)
                  |
                  v
             XS module
        secure buffer + zeroize()
                  |
                  v
             HKDF / audit code
                  |
                  v
             PRK output only

             zeroize(IKM)
```

The key idea is: **Python never owns the IKM as a Python object.**

For example, the XS side could allocate:

```c
unsigned char *ikm = malloc(len);

read(fd, ikm, len);

/* expose only a capsule/handle to Python */

...

explicit_bzero(ikm, len);
free(ikm);
```

where `explicit_bzero()` (or an equivalent) prevents the compiler from optimizing the wipe away.

A minimal Perl XS interface might expose something like:

```perl
my $ctx = SecureBuffer::load("ikm.bin");

my $prk = derive_hkdf($ctx);

$ctx->zeroize();
undef $ctx;
```

The Python side would only receive:

```python
prk = secure_hkdf_from_handle(handle)
```

not:

```python
ikm = open("ikm.bin","rb").read()
prk = hkdf(ikm)
```

because the second version creates Python-managed immutable copies.

For your "Zero Material Standard" type claim, the important distinction is:

| Approach                        | Claim strength                                |
| ------------------------------- | --------------------------------------------- |
| Python `bytes` + `del`          | lifetime reduction only                       |
| Python `bytearray` overwrite    | best-effort zeroization                       |
| C/Rust secure buffer            | explicit memory control                       |
| XS wrapper around secure buffer | Python orchestration + native secret handling |
| SGX/TEE enclave                 | hardware-isolated secret boundary             |

A hybrid XS approach is actually a reasonable middle layer: you keep the productivity of Python for the audit/proof logic while moving the **secret-bearing primitive** into a component where memory ownership is explicit.

For an audit artifact like `proof-122b_audit.py`, I would keep the script itself deterministic and public, and have something like:

```
run_audit.py
        |
        +-- SecureIKM.xs
              |
              +-- load_once()
              +-- derive()
              +-- zeroize()
```

Then the audit can honestly state:

> "The verification layer never receives the root secret material; it receives only derived verification artifacts. Secret allocation and destruction occur in a zeroizable native boundary."

That is a substantially stronger security argument than trying to prove Python garbage collection behavior.


## going further ...

Perl fork the python ...

 **forking a short-lived Python worker from Perl can improve the security boundary**, but the statement "when Python exits all is clear" needs some precision.

The model becomes:

```
Perl supervisor
    |
    | fork/exec
    v
Python worker
    |
    | load IKM
    | derive PRK
    | output only derived material
    |
    exit()
```

Advantages:

### 1. Process isolation

When Python exits:

* the OS releases the entire virtual address space
* Python heap objects disappear
* garbage-collected objects disappear
* temporary buffers disappear

You no longer depend on Python's garbage collector to clean up references.

This is a **big improvement** over:

```
long-running Python process
    |
    IKM stays somewhere in heap
```

because the lifetime is bounded by the worker process.

### 2. No accidental retention

A common problem:

```python
global_cache.append(ikm)
logger.debug(ikm)
exception_traceback -> locals -> ikm
```

A worker process limits the blast radius. When it dies, those references are gone with it.

### 3. Perl can enforce the lifecycle

For example:

```
perl
 |
 +-- create pipe
 |
 +-- fork()
 |
 +-- send one-time input
 |
 +-- python derives
 |
 +-- receive PRK
 |
 +-- waitpid()
 |
 +-- verify worker terminated
```

The parent never needs to keep the IKM.

---

However, two important caveats:

### Caveat 1 — exit is not cryptographic zeroization

The OS normally just marks pages as free. It does **not necessarily overwrite RAM immediately**.

So:

```
exit()
   |
   v
memory returned to kernel
```

is not equivalent to:

```
explicit_bzero(secret)
   |
   v
RAM contains zeros
```

For most threat models, process destruction is acceptable. For high-assurance crypto claims, explicit wiping before exit is still preferable.

---

### Caveat 2 — fork copies memory

If Perl already has the secret before forking:

```
Perl
 |
 | IKM exists
 |
 fork()
 /    \
Perl  Python
```

then copy-on-write pages may exist in both processes.

The safer order is:

```
Perl supervisor
      |
      fork/exec python
             |
             python reads IKM file
             |
             derive
             |
             wipe
             |
             exit
```

The parent never touches the secret.

---

For your `proof-122b_audit.py` concept, I would actually structure it as:

```
proof-runner.pl          (trusted orchestrator)
        |
        |
        +---- fork/exec ----> proof-122b_worker.py
                                  |
                                  + read ikm file
                                  + HKDF extract
                                  + produce audit proof
                                  + zeroize()
                                  + exit(0)
```

Then the strongest claim you can make is:

> "The verification process is single-purpose, receives the root material only inside an ephemeral worker, derives the audit artifact, destroys its secret state, and terminates."

That is much easier to defend than a monolithic Python program.

For an even stronger version, replace the Python worker with a tiny Rust/C helper and keep Python only as the audit/report layer.

