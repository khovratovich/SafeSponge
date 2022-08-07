# SAFE (Sponge API for Field Elements) – A Toolbox for ZK Hash Applications 

*[Dmitry Khovratovich](mailto:khovratovich@gmail.com) – Ethereum Foundation and Dusk Network 
[JP Aumasson](mailto:jp@taurusgroup.ch) – Taurus and Inference
[Porçu Quine](mailto:porcuquine@gmail.com?) – Lurk Lab and Protocol Labs*


We define a unified Sponge API for Field Elements (SAFE), which provides ZK proof systems designers with a secure and efficient framework for hashing, encryption, and applications thereof (commitment schemes, Fiat-Shamir transforms, AEAD, and so on). We do not restrict the permutation algorithm nor the field type, thus SAFE can be instantiated with established constructions.

SAFE is implemented by Filecoin's [Neptune](https://github.com/filecoin-project/neptune/tree/master/src/sponge), which is our reference implementation (in Rust).   

## 1. Introduction

[Sponges](https://keccak.team/sponge_duplex.html) are a technique to build cryptographic primitives from a single permutation: hash functions, MACs, authenticated encryption schemes, PRNGs, and others. Examples of sponges include

* [Keccak](https://keccak.team/keccak.html), the basis for SHA-3, and Ethereum's built-in hash; 
* [Poseidon](https://www.poseidon-hash.info/), one of the most popular algebraic hash functions, as designed to be efficient in ZK proof systems' circuits.

When operating in [duplex mode](https://keccak.team/sponge_duplex.html), a sponge can be seen as stateful object that can ingest input ("absorb") and produce output ("squeeze") at any time and in arbitrary order. However, the original duplex specification sees the input and output as raw bytes, and leaves application-specific encoding to the users.

However, in ZK proof systems (ZKPs) hash functions often process field elements, rather than raw bytes. Performance being critical to reduce the proof generation and verification cost, dedicated "field-friendly", algebraic hash functions were designed, most of which are sponges. These include for example [Poseidon](https://www.poseidon-hash.info/), [Rescue](https://eprint.iacr.org/2019/426), [MIMC](https://byt3bit.github.io/primesym/mimc/), and [Reinforced Concrete](https://eprint.iacr.org/2021/1038). But their integration in ZKPs can benefit from safety and performance optimization, owing to the following issues:

* When the domain consists of prime field elements, as large integers, a straightforward implementation of existing padding schemes bloats the input and reduces ZKPs performance. 
* Developers often have to craft custom modes of operation, which leads to a variety of different interfaces, some of which may be unsafe.
* In Fiat-Shamir transforms, hash functions often process a (relatively short) pre-defined sequence of input values, each of fixed size, which allows for optimizations of the hash.
* Conversely, hash functions calls are often not properly domain-separated in places where they ought to be.

To address these, to reduce the workload of developers, and as a first step towards a unified cross-platform interface, we propose a **generic API** for sponge functions that can be instantiated with various permutations of different size, to create the functionalities required in ZKPs.

### 1.1. Applications

Our API can be used in the  applications and protocols that need the following:

* **Hashing** with fixed-length input, as found in commitment schemes, Merkle trees, and signatures.
* **Fiat-Shamir** transforms and other stateful oracle simulations, where the sequence and size of input values is fixed and known in advance.
* **Authenticated encryption** of fixed-length messages.
* **Pseudo-random generation** of field elements from a seed.

**Limitation:** The SAFE API *does not support variable-length hashing when the length of data hashed is unknown in advance*. This is due to its little usage vs. the extra complexity and performance overhead. We nonetheless explain how to extend our API to support such use cases. 

### 1.2. Choosing a permutation

Most sponge designs have a permutation that can be reused with our API, in particular the aforementionned ZK-friendly designs. The two main parameters to take into account, aside from the capacity, are:

1. **The algebraic compability** with your application's data. For example, Poseidon has specific instances for the scalar fields of the BLS12-381 curve and of the Ed25519 signing scheme.
2. **The number of rounds**, and more generally the construction's security margin: in general, the more rounds the more security margin, up to a certain point. Likewise, fewer rounds lead to better performance, but too few rounds is risky.

We recommend choosing a permutation and implementation that have already been "battle-tested", that is, designed and reviewed by cryptanalysts, and already deployed.

### 1.3. Choosing a security level

The **state** of a sponge function is seen as an array of width $n = r + c$ bits, where $r$ and $c$ are the **rate** and the **capacity**, respectively. The capacity can be thought of as twice the security level, meaning that a capacity $c = 256$ bits gets roughly 128-bit security against collisions and preimages – as long as the output is at least 256-bit.

When working with field elements, it's more convenient to measure in field elements rather than in bits. This lead to the concept of **arithmetic capacity** (see 4.3 in the [Rescue/Vision paper](https://eprint.iacr.org/2019/426)). In the following, we will adopt this convention and count capacity and rate *in field elements*, instead of bits. Thus, a rate $r=2$ means that up to 2 field elements can be absorbed. 

For example, the Poseidon hash family has a state consisting of field elements, and its main instances works with 255-bit representations of field elements, and an arithmetic capacity of one or two elements, for 128- and 256-bit security, respectively.

The **security level** to choose depends on the use case, but as a rule of thumb 128-bit security [should be enough](https://eprint.iacr.org/2019/1492) for most applications. Note that the security level of the hash function should be consistent with that of other cryptographic schemes in your system. For example, it's probably of little value to have a 256-bit-secure hash if all the other primitives have at most 128-bit security, for example.

The main security notions applicable to hash functions in our context are, from the easiest to achieve (and hardest to break):

* **Preimage resistance**: Given a sponge output $Z$ it is infeasible to find a parameter $P$ and input $\mathcal{Y}$ that yields $Z$.
* **Collision resistance** for sponge calls: For any protocol it is infeasible to find two different inputs $\mathcal{Y}_1,\mathcal{Y}_2$ that yield outputs with the same prefix of a given length (say, 100 bits).
* **Cross-protocol collision resistance**: For a given protocol with  sponge tag $T_1$ it is infeasible to find another protocol with a distinct tag $T_2$ and two different inputs $\mathcal{Y}_1,\mathcal{Y}_2$ that yield outputs with the same prefix of a given length (say, 100 bits). Depending on the use case, cross-protocol security may or may not be needed. 

## 2. SAFE definition
![](https://hackmd.io/_uploads/SyH42eT6c.png)



### 2.1 API overview

* We assume a sponge width of $n=r+c$ field elements, where $r$ is the rate and $c$ the capacity.
* $\mathbb F$ is the finite field type, thus elements of $\mathbb F^L$ are vectors of $L$ field elements.  
* We define input/output arguments by their type, and only add an argument'ss name when needed by our description.
* $\mathtt{Length}$ is the length type, an unsigned integer properly bounded counting the number field elements. In Rust implementations, for example, $\mathtt{Length}$ may correspond to the `usize` type, with potential enforcement of upper bounds on the input size (thus on value of the received `usize` element). 
* $\mathtt{State}$ is the type of the internal state, consisting of field elements and other variables (as detailed in 2.3).


A SAFE sponge object should expose the following operations to protocol designers (details are described in 2.3 and 2.4):

* $\mathsf{START}(\mathtt{IOPattern},\mathtt{DomainSeparator}) 
\to \mathtt{State}$: This initializes the internal state of the sponge, modifying up to $c/2$ field elements of the state. It's done once in the lifetime of a sponge. 
* $\mathsf{ABSORB}(\mathtt{State}, \mathtt{Length}: L, \mathbb F^L: X[L])\to \mathtt{State}$: This injects $L$ field elements to the state from the array $X$, interleaving calls to the permutation as defined [in 2.4](#24-Detailed-API). It also checks if the current call matches the IO pattern.
* $\mathsf{SQUEEZE}(\mathtt{Length}: L)\to \mathbb F^L$: This extracts $L$ field elements from the state, interleaving calls to the permutation as defined [in 2.4](#24-Detailed-API). It also checks if the current call matches the IO pattern.
* $\mathsf{FINISH}(\mathtt{Length})\to\mathtt{Result}$: This marks the end of the sponge life, preventing any further operation. In particular, the state is erased from memory. The result is `OK`, or an error.

The general workflow of a sponge is then as follows:

1. First, a protocol initializes the sponge: $\mathsf{START}(S[],D)$ call where $S$ is a sequence of future calls and their respective lengths (what we call "IO pattern") and $D$ is the domain separator. Note that you can also start from a precomputed state, but said state must come from a properly initialized sponge.
2. The protocol makes a chain of calls $C_1,C_2,\ldots, C_\ell$, whose input lengths and types correspond to $S$.   Each $C_i$ is either an $\mathsf{ABSORB}$ or a $\mathsf{SQUEEZE}$ call.
3. The protocol closes the sponge with a $\mathsf{FINISH}()$ call.


> **REMARK**: everal IO patterns can belong to the same equivalence class, and thus leading to identical instances. This is because consecutive calls of a same type ($\mathsf{ABSORB}$ or $\mathsf{SQUEEZE}$) are **aggregated** to define the initial state. An application that needs to absorb $L>1$ elements in a row can thus do it one by one (with $L$ calls to $\mathsf{ABSORB}$), or with a single call including the $L$ elements. See 2.3 for details. 


Important notes:

* **Dealing with non-field elements**: The API assumes that the input is (represented as) field elements, however applications may need to process other data types. It is the responsibility of users to properly encode such inputs as field elements. If objects of different types are processed by multiple runs of a same instance, at the same position, then some signalling of the input type is required to avoid collisions between different elements of distinct types encoded identically (incurring a performance overhead).
* **Precomputing a state:** Multiple "forks" of a sponge can be created, by storing the state after a given number of operations, and restarting from it with distinct $\mathsf{ABSORB}$ calls in distinct branches. Note that all forks must do the same calls sequence, as specified to the $\mathsf{START}$ call.  




### 2.2. Sponge state

Let $c<n$ be the number of capacity elements. The sponge state consists of the following elements:

* Permutation state $V\in \mathbb{F}^n$.
* Hasher $\mathcal{H}$, a cryptographic hash function producing 128-bit digests, by default a SHA3-256 instance truncated to its first 128 bits.
* Permutation $\mathcal{P}$, a bijective mapping that maps $\mathbb{F}^n$ to itself. 
* Parameter tag $T$.
* Absorb position $\textsf{absorb_pos}\leq n-c$.
* Squeeze position $\textsf{squeeze_pos}\leq n-c$. 
* IO pattern expected (as defined by $\mathsf{START}$). 


### 2.3. Sponge instance, IO pattern, and tag

A sponge **instance** is characterized by a tag, which is derived from an **IO pattern**, that is, its a sequence of absorb phases and squeeze phases and their respective number of field elements. However, different IO patterns may lead to the same tag:

For example, the following IO patterns lead to a *distinct* tag/instance:
* Pattern 1:
    * $\mathsf{ABSORB}(L=3)$
    * $\mathsf{SQUEEZE}(L=1)$.
* Pattern 2:
    * $\mathsf{ABSORB}(L=2)$
    * $\mathsf{SQUEEZE}(L=1)$

However, the following pattern has the same
tag/instance  as Pattern 1, as per our aggregation mechanism:
* Pattern 3:
    * $\mathsf{ABSORB}(L=2)$;
    * $\mathsf{ABSORB}(L=1)$;
    * $\mathsf{SQUEEZE}(L=1)$. 

The **tag** of an instance is used as an initial value, to ensure that distinct instances behave like distinct functions. Using distinct tags for different, non-equivalent usage patterns avoids trivial collisions between input sequences of different length, where a "non-input" element is replaced by a zero element in the colliding message (this would lead to a collision because of the lack of padding).

Furthermore, for applications that need to distinguish equivalent IO patterns, a *domain separator* can be used. 

A **tag** is calculated from an IO pattern and a domain separator as follows: 

1. **Encode** the IO pattern as a list of 32-bit words, whose MSB set to 1 for $\mathsf{ABSORB}$ calls and to 0 for $\mathsf{SQUEEZE}$ calls. For example, an instance that does 2 $\mathsf{ABSORB}$ calls with 3 elements each and then does one $\mathsf{SQUEEZE}$ call with 3 elements is described by the three words `[0x80000003, 0x80000003, 0x00000003]`.
2. **Aggregate** any contiguous $\mathsf{ABSORB}$ or $\mathsf{SQUEEZE}$ calls within a single call: in our example, we would replace `[0x80000003, 0x80000003]` with a single `0x80000006`.
3. **Serialize** the list of words into a byte string and append to it the domain separator $D$: for example, if $D$ is the two-byte sequence `0x4142`, then the example above would yield the string (if big-endian convention is used): `0x80000006000000034142`. 
4. **Hash** the string obtained with the hasher $\mathcal{H}$ to a 128-bit tag $T$ (truncating the hash to its first 128 bits if needed).

Given its tag string, an instance admits an arbitrary number of **executions**, which are in addition characterized by an input $\mathcal Y\in (\mathbb F^r)^\star$. 

> **REMARK**: If the hash function used to create the tag received field elements rather than byte strings, and can directly process calls 32-bit integers as field elements, then the serialization mechanism (incl. endianness aspects) is not needed.

> **REMARK**: Implementations may store the IO pattern as a sequence of bytes (e.g. `uint8`) rather than 32-bit words, since each byte corresponds to a call whose length is bounded by the rate, unlikely to exceed 255. However, tag computation requires 32-bit words because the aggregation of calls may lead to lengths exceeding 255.


### 2.4. Detailed API

Each call to $\mathsf{ABSORB}$ or $\mathsf{SQUEEZE}$ both:

* Writes to or read the rate part of the permutation state and calls $\mathcal{P}$ when needed.
* Verifies its own parameters against the initially supplied IO pattern ("early abort" misuse detection).

When all calls are done, the $\mathsf{FINISH}$ operation verifies that no call is left undone. 

> **REMARK**: Each call verifies "as it goes" that the correct sequence of calls is performed, as prescribed by the IO pattern initially fed to $\mathsf{START}$. Executing a distinct IO pattern, even if equivalent after aggregation, would lead to an error.

$\mathsf{START}(\mathtt{IOPattern}: IO[L],\mathtt{DomainSeparator}: D)$:
* Given an IO pattern $IO$ (as a list of calls with the respective number of elements) and a byte string $D$ used as domain separator, compute the tag $T$ as described in 2.3.
* Set the permutation state to all zeros and add $T$ to the first 128 bits of the state (with respect to the field's addition). If field elements are 128-bit or more, $T$ is converted to a field element. Otherwise $T$ is parsed as two or more field elements.
* Set both absorb and squeeze positions to zero: $\textsf{absorb_pos} = \textsf{squeeze_pos} = 0$.
* Set the IO count to zero: $\textsf{io_count = 0}$.
* Set the IO pattern expected to $IO[L]$.

> **REMARK**: Memory-constrainted applications may not store the IO pattern expected, but only the tag (if significantly shorter), and then recompute the tag from the IO pattern executed when finalizing the sponge. In that case, the continuous verification of the IO pattern does not need to be done as part of $\mathsf{ABSORB}$ and $\mathsf{SQUEEZE}$ calls. 

$\mathsf{ABSORB}(L, X[L])$:

* If $L==0$, return
* For $i = 0, 1 ,.., L-1$
	* If $\textsf{absorb_pos} == (n-c)$  then
		* Set $V = \mathcal P(V)$, to permute the state.
		* Set $\textsf{absorb_pos}=0$, to restart writing at the zero offset.
	* Add $X[i]$ to the state element at $\textsf{absorb_pos}$.   
	* Do $\textsf{absorb_pos}++$.
* Compute the 32-bit encoding of $L$ to the IO pattern.
* Verify that the word obtained is equal to the $\textsf{io_count}$-th word of the IO pattern expected, abort upon mismatch (and erase the state).
* Do $\textsf{io_count}++$ 
* Set $\textsf{squeeze_pos} = (n-c)$, to force a permute at the start of the next $\mathsf{SQUEEZE}$.

$\mathsf{SQUEEZE}(L) \to Y[L]$:

* If $L==0$, return
* For $i = 0, 1 ,.., L-1$
	* If $\textsf{squeeze_pos}==(n-c)$ then
		* Set $V = \mathcal P(V)$, to permute the state
		* Set $\textsf{squeeze_pos}=0$, to restart reading ouput at the zero offset 
		* Set $\textsf{absorb_pos}=0$, to start writing at the zero offset in the next $\mathsf{ABSORB}$
	* Set $Y[i]$ to the state element at position $\textsf{squeeze_pos}$
	* Do $\textsf{squeeze_pos}++$
* Compute the 32-bit encoding of $L+2^{31}$ to the IO pattern.
* Verify that the word obtained is equal to the $\textsf{io_count}$-th word of the IO pattern expected, abort upon mismatch (and erase the state).
* Do $\textsf{io_count}++$ 

> **REMARK**: We do not set $\textsf{absorb_pos}$ to $(n-c)$ as in ABSORB as we may want the state to absorb at the same positions that have been squeezed. Example is [authenticated encryption](#35-Authenticated-encryption).
 
$\mathsf{FINISH}()$:
* Check that $\textsf{io_count}$ equals the length of the IO pattern expected. Return an error otherwise.
* Erase the state and its variables.



### 2.5. Internal API recommendation

The permutation state should not be directly manipulated as a mere vector of values. Instead, it should only expose such functions:

* `InitializeCapacity(Tag)`: Sets the first bits of the capacity elements to the tag.
* `ReadRateElement(Offset) -> FieldElement`: Reads the state element at position `Offset`
* `AddRateElement(Offset, FieldElement)`: Add in the field an element to the state at position `Offset` 
* `Permute()`: Permutes the state

## 3. Functionalities

### 3.1. Hashing

The simplest way to hash $L$ elements $X=X_1, X_2,\dots, X_{L}$ is to do a single call $\mathsf{ABSORB}(L, X)$ followed by a single $\mathsf{SQUEEZE}$, with the length of the desired output. These calls should be preceeded by a $\mathsf{START}$ call and succeeded by a $\mathsf{FINISH}$ call.

If the $L$ elements are absorbed using more than one call -- for example, via $\mathsf{ABSORB}(1, X_1)$ followed by $\mathsf{ABSORB}(L-1, (X_2,\dots,X_{L}))$ -- then the resulting hash will *not* change.

### 3.2. Merkle tree 

Consider a binary tree whose leaves and nodes are field elements, for example from a 256-bit field $\mathbb{F}$. Each inner node with children nodes $X_1,X_2 \in \mathbb F$ is then obtained as follows:

* $\mathsf{START}(IO[3], D)$ with $IO$ the encoding of two $1$-element $\mathsf{ABSORB}$s and one $1$-element $\mathsf{SQUEEZE}$ (that is, `[0x81, 0x81, 0x01]`) and $D$ an arbitrary (possibly empty) domain separator
* $\mathsf{ABSORB}(1, X_1)$ 
* $\mathsf{ABSORB}(1, X_2)$
* $Y\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{FINISH}()$

If $\mathsf{FINISH}$ succeeds, then $Y$ is the node value above the two nodes hashed.

Alternatively, the two $\mathsf{ABSORB}$ calls can be replaced by a single $\mathsf{ABSORB}(2, (X_1,X_2))$, which will yield the same result. Note that the $IO$ supplied to $\mathsf{START}$ is then replaced by `[0x82,0x01]`.

This construction generalizes to binary trees whose elements are tuples, in some $\mathbb{F}^L, L>1$.

If computed with SHA3-256 with big-endian word-to-byte conversion, the 16-byte tag of our example would then be the hash of the serialized words `[0x800000002,0x00000001]` (note that the two $\mathsf{ABSORB}$s are aggregated), that is:

```python
hashlib.sha3_256(b'\x80\x00\x00\x02\x00\x00\x00\x01').hexdigest()[:32]
'3be11cba2e57c1d9e7ff6a72538baeef'
```

With a domain separator `\x41\x42`, the tag would then be

```python
hashlib.sha3_256(b'\x80\x00\x00\x02\x00\x00\x00\x01\x41\x42').hexdigest()[:32]
'09db848230d0b7d463bec1bf621b7844'
```

### 3.3. Commitment scheme 

Consider a $1$-element commitment to three values $X_1,X_2,X_3\in \mathbb F^2$, that is, each element $X_i$ is a pair of field elements. The commitment is then obtained as follows:

* $\mathsf{START}(IO[4], D)$ with $IO$ the encoding of three $2$-element $\mathsf{ABSORB}$s and one $1$-element $\mathsf{SQUEEZE}$ (that is, `[0x82, 0x82, 0x82, 0x01]`) and $D$ an arbitrary (possibly empty) domain separator
* $\mathsf{ABSORB}(2, X_1)$ 
* $\mathsf{ABSORB}(2, X_2)$
* $\mathsf{ABSORB}(2, X_3)$
* $Y\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{FINISH}()$

If $\mathsf{FINISH}$ succeeds, then $Y$ is the commitment value. This construction generalizes to other input and output lengths.

Equivalently, the three $\mathsf{ABSORB}$ calls can be replaced by a single $\mathsf{ABSORB}$ taking 6 field elements.

> **REMARK**: The API does not distinguish the cases of (say) 
> * 2 elements A and B in $\mathbb F$, and 
> * 1 element (A,B) in $\mathbb F^2$.
> 
> In both cases, the sponge will absorb A and B, and produce the same result. If an application needs to distinguish those two cases, it must add some additional signalling, for example as a domain separator.

If computed with SHA3-256 with big-endian word-to-byte conversion, the 16-byte tag of our example would then be the hash of the serialized words `[0x800000006,0x00000001]` (note that the three $\mathsf{ABSORB}$s are aggregated), that is:

```python
hashlib.sha3_256(b'\x80\x00\x00\x06\x00\x00\x00\x01').hexdigest()[:32]
'c1dff57614db1d8e3ea1d60be1124497'
```

### 3.4. Interactive protocol

Consider the following example protocol:

1. Parties agree on the common input $Z\in\mathbb{F}^z$
2. Prover prepares and sends proof elements $\pi_1\in\mathbb{F}^{L_1}$ and $\pi_2\in\mathbb{F}^{L_2}$
3. Verifier responds with challenge $c_1\in\mathbb{F}$
4. Prover prepares and sends proof element $\pi_3\in\mathbb{F}^{L_3}$
5. Verifier responds with challenges $c_2,c_3\in\mathbb{F}$
6. Prover sends final proof $\pi_4$

The challenge generation using Fiat-Shamir  would then look as follows:

* $\mathsf{START}(IO[6], D)$ with $IO$ be the encoding of the following calls, and $D$ an arbitrary domain separator;
* $\mathsf{ABSORB}(z,Z)$ 
* $\mathsf{ABSORB}(L_1,\pi_1)$ 
* $\mathsf{ABSORB}(L_2,\pi_2)$
* $c_1\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{ABSORB}(L_3,\pi_3)$
* $c_2\leftarrow \mathsf{SQUEEZE}(1)$
* $c_3\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{FINISH}()$
    
### 3.5. Authenticated encryption

Authenticated encryption with SAFE is a simplification of the SpongeWrap mode (from the [Duplex paper](https://keccak.team/files/SpongeDuplex.pdf)): Encryption of $b$ blocks of data with the key $K\in\mathbb{F}^k$ and nonce $N\in\mathbb{F}^m$, where block $D_i$ consists of $L_i$ field elements, is done as follows:

* $\mathsf{START}(IO[], D)$ with $IO$ be the encoding of the subsequence calls, and $D$ an arbitrary domain separator
* $\mathsf{ABSORB}(k,K)$
* $\mathsf{ABSORB}(m,N)$
*  $C_1\leftarrow \mathsf{SQUEEZE}(L_1)$
* $\mathsf{ABSORB}(L_1,D_1)$ 
*  $C_2\leftarrow \mathsf{SQUEEZE}(L_2)$
* $\mathsf{ABSORB}(L_2,D_2)$ 
* ...
*  $C_b\leftarrow \mathsf{SQUEEZE}(L_b)$
* $\mathsf{ABSORB}(L_b,D_b)$ 
* $S\leftarrow \mathsf{SQUEEZE}(t)$
* $\mathsf{FINISH}()$
    
Upon success of $\mathsf{FINISH}()$ and of previous calls, the string $(C_1+D_1)||(C_2+D_2)||\cdots ||(C_b+D_b)||S$ will be the ciphertext, where "$+$" denotes addition in $\mathbb F$. Here $t$ is the tag length, usually set to be at least 128 bits long.

> **REMARK**: This construction is the most efficient when $L_i \equiv r \mod n$, that is, all blocks fit the rate parameter of the sponge. This should be set by the protocol designer.

Decryption of $b$ blocks of data (plus $t$ extra tag elements $E_t\in\mathbb F^t$) on the key $K\in\mathbb{F}^k$ and nonce $N\in\mathbb{F}^m$, where block $E_i$ consists of $L_i$ field elements, is done as follows:

* $\mathsf{START}(IO[], D)$ with $IO$ be the encoding of the subsequence calls, and $D$ an arbitrary domain separator
* $\mathsf{ABSORB}(k, K)$
* $\mathsf{ABSORB}(m, N)$
*  $C_1\leftarrow \mathsf{SQUEEZE}(L_1)$
* $\mathsf{ABSORB}(L_1, E_1-C_1)$ 
*  $C_2\leftarrow \mathsf{SQUEEZE}(L_2)$
* $\mathsf{ABSORB}(L_2, E_2-C_2)$ 
* ...
*  $C_b\leftarrow \mathsf{SQUEEZE}(L_b)$
* $\mathsf{ABSORB}(L_b, E_b-C_b)$ 
* $S\leftarrow \mathsf{SQUEEZE}(t)$
* If $S\neq E_t$ return ERROR
* $\mathsf{FINISH}()$

Upon success of $\mathsf{FINISH}()$ and of previous calls, and if $S$ matches $E_t$, then the string $(E_1-C_1)||(E_2-C_2)||\cdots ||(E_b-C_b)$ is returned as plaintext.

This mode can be adapted to supported associated data (authenticated but not encrypted), in the same vein as the SpongeWrap mode.

### 3.6. Stream cipher and PRNG

A stream cipher generates a pseudo-random stream from a secret key and a not necessarily secret nonce, while a PRNG generates a pseudo-random stream from a seed. These can thus be instantiated with a similar sponge object to generate a pseudo-random stream $C_1, \dots, C_b$, where $C_i$ contains $L_i$ field elements: 

* $\mathsf{START}(IO[], D)$ with $T$ be the encoding of the subsequent calls, and $D$ an arbitrary domain separator
* For the PRNG case, given a seed $S\in\mathbb F^s$:
    * $\mathsf{ABSORB}(s,S)$
* For the stream cipher case, given a key $K\in\mathbb F^k$ and a nonce $N\in \mathbb F^m$
    * $\mathsf{ABSORB}(k,K)$
    * $\mathsf{ABSORB}(m,N)$
*  $C_1\leftarrow \mathsf{SQUEEZE}(L_1)$ 
*  $C_2\leftarrow \mathsf{SQUEEZE}(L_2)$
* ...
*  $C_b\leftarrow \mathsf{SQUEEZE}(L_b)$ 
* $\mathsf{FINISH}()$

For the stream cipher case, the plaintext $D_1,\dots,D_b$ with $D_i$ consists of $L_i$ field elements is then encrypted to $(C_1+D_1)||(C_2+D_2)||\cdots ||(C_b+D_b)$.

## Appendices

### "Infinite-length" PRNG and (authenticated) encryption

The authenticated encryption and stream cipher (with unique nonces), as well as PRNG mode (with a fixed-length seed) can be securely instantiated even if the IO pattern (and thus the tag) is not known in advance. In such a case, the state is initialized to elements $1,2,3, .., n$, to distinguish it from the all-zero state used in the fixed-length mode.

In that case, the calls cannot, and thus do not enforce the IO pattern. Also, the sponge output can be used prior to the $\mathsf{FINISH}$ call, which thus serves to "close" the instance and does not enforce an IO pattern either.

### Faster hasher with universal hashing

To avoid computing a costly cryptographic hash as the hasher $\mathcal H$, one can use a universal hash function, such as the following:

Let $X$  be a 128-bit constant, which is co-prime to $2^{128}$. The input is parsed as a sequence of 128-bit integers $A=(a_0,a_1,\ldots,a_n)$ and hashed to $$
\sum a_iX^i \bmod{2^{128}}
$$
    
In that case, cross-protocol collision resistance property is reduced, as an attacker who controls the IO pattern can choose two patterns from distinct equivalent classes that yield the same tag. 

Systems wherein the IO patterns and fixed by design may only need that weaker notion. However, if the IO patterns are fixed, then the tag can be precomputer with a costly hash.
