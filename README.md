# SAFE (Sponge API for Field Elements) – A Toolbox for ZK Hash Applications 

*[Dmitry Khovratovich](khovratovich@gmail.com), Ethereum Foundation and Dusk Network 
[JP Aumasson](jp@taurusgroup.ch), Taurus*


We define a unified, misuse-safe API for hashing and encryption mechanisms based on a ZK-friendly sponge function working with finite field elements (generally of 64 bits or more). 

## 0. TODOs / open questions

* Instance unicity per call pattern: 
    * Pass sequence of calls to START as a bytes sequence; hash them to get the 128b init string; keep comparing words as we do calls; alternative = dont compare but hash at the end); also, use bytes instead of 32b words
    * Explain the value of this: prevent trivial collisions, otherwise possible due to the streamlined padding-free design
    * Hasher: any crypto hash
* Ok to distinguish Absorb(1)+Absorb(1) from Absorb(2)? (via the Tag): OPEN, ASK PEOPLE
* Do an unlimited AE/stream cipher/PRNG? (with a special, domain-separated tag): for AE, need padding
* Absorb with ADD ~~vs ERASE~~
* Test vectors for the tag: code a few use cases and give test vectors for the tag hash etc. 
* Non-field elements processing: leave it up to users


## 1. Introduction

Cryptographic [**sponges**](https://keccak.team/sponge_duplex.html) are a technique to build cryptographic primitives from a single permutation: hash functions, MACs, authenticated encryption schemes, and others. The [SHA-3/Keccak](https://keccak.team/keccak.html) hash standard is a sponge and one of the most popular algebraic hash functions -- as used in zero-knowledge proof systems -- is also a sponge ([Poseidon](https://www.poseidon-hash.info/)).

A sponge, more precisely its [duplex mode](https://keccak.team/sponge_duplex.html), can be seen as stateful object that can receive input ("absorb") and return output ("squeeze") at any time and in arbitrary order. However, the generic specification sees the input and output as raw bytes, and leaves application-specific encoding to the users, which requires some adaptions to work efficiently within zero-knowledge (ZK) proof systems.

**ZK proof systems** (ZKPs) often process field elements and require optimized cryptographic logic to reduce the circuit size, and thus the proof generation and verification cost. Recent  hash designs that target ZK proof systems ([Poseidon](https://www.poseidon-hash.info/), [Rescue](https://eprint.iacr.org/2019/426), [MIMC](https://byt3bit.github.io/primesym/mimc/), [Reinforced Concrete](https://eprint.iacr.org/2021/1038)) use sponges. But their integration in ZKPs can benefit from safety and performance optimization, owing to the points:

* When the domain consists of prime field elements, as large integers, a straightforward implementation of existing padding schemes bloats the input and reduces ZKPs performance. 
* Developers often have to craft custom modes of operation, which leads to a variety of different interfaces, some of which may be unsafe.
* In Fiat-Shamir transforms, hash functions often process a (relatively short) pre-defined sequence of input values, each of fixed size, which allows for optimizations of the hash.
* Conversely, hash functions calls are often not properly domain-separated in places where they ought to be.

To address these, to reduce the workload of developers, and as a first step towards a unified cross-platform interface, we propose a **generic API** for sponge functions that can be instantiated with various permutations of different size, to create the functionalities required in zero-knowledge proof systems and many other applications.

### 1.1. Applications and limitations

Our API can be used in the  applications and protocols that need the following:

* **Hashing** with fixed-length input, as found in commitment schemes, Merkle trees, and signatures.
* **Fiat-Shamir** transforms and other stateful oracle simulations, where the sequence and size of input values is fixed and known in advance.
* **Authenticated encryption** of fixed-length messages.

The API *does not support variable-length* hashing, that is, when the length of data hashed is unknown in advance. This is due to its little usage vs. the extra complexity and performance overhead. We nonetheless explain how to extend our API to support such use cases. 

### 1.2. Choosing a permutation

Most sponge designs have a permutation that can be reused with our API, in particular the aforementionned ZK-friendly designs. The two main parameters to take into account (aside from the capacity, as discussed below in 1.3) are:

1. **The algebraic compability** with your application's data. For example, Poseidon has specific instances for the scalar fields of the BLS12-381 curve and of the Ed25519 signing scheme.
2. **The number of rounds**, and more generally the construction's security margin: in general, the more rounds the more security margin, up to a certain point. Likewise, fewer rounds lead to better performance.

We recommend choosing a permutation and implementation that have already been "battle-tested", that is, designed and reviewed by cryptanalysts, and already deployed in production.

### 1.3. Choosing a security level

The **state** of a sponge function is seen as an array of width $n = r + c$ bits, where $r$ and $c$ are the **rate** and the **capacity**, respectively. The capacity can be thought of as twice the security level, meaning that with a capacity $c = 256$ you get roughly 128-bit security against collisions and preimages (as long as the output is at least 256-bit).

When dealing with field elements, it's often more convenient to think in terms of field elements rather than in terms of bits. This lead to the concept of **arithmetic capacity** (see 4.3 in the [Rescue/Vision paper](https://eprint.iacr.org/2019/426)). In the following, we will adopt this convention and count capacity and rate *in terms of field elements*, instead of bits.

For example, the Poseidon hash family has a state consisting of field elements, and its main instances works with 255-bit representations of field elements, and an arithmetic capacity of one or two elements, for 128- and 256-bit security, respectively.

The exact **security level** required depends on the use case, but as a rule of thumb 128-bit security should be enough for most applications. Note that the security level of the hash function should be consistent with that of other cryptographic schemes in your system (it's probably of little use to have a 256-bit-secure hash if all the other primitives have at most 100-bit security, for example).

For completeness, we describe the relevant security notions, from the easiest to achieve (and hardest to break):

* **Preimage resistance**: Given a sponge output $Z$ it is infeasible to find a parameter $P$ and input $\mathcal{Y}$ that yields $Z$.
* **Collision resistance** for sponge calls: For any protocol it is infeasible to find two different inputs $\mathcal{Y}_1,\mathcal{Y}_2$ that yield outputs with the same prefix of a given length (say, 100 bits).
* **Cross-protocol collision resistance**: For a given protocol with  sponge tag $T_1$ it is infeasible to find another protocol with a distinct tag $T_2$ and two different inputs $\mathcal{Y}_1,\mathcal{Y}_2$ that yield outputs with the same prefix of a given length (say, 100 bits).

Depending on the use case, cross-protocol security may or may not be needed. 

## 2. SAFE definition

This section describes our sponge API for field elements (SAFE).

### 2.1 High-level API

* We assume a sponge width of $n=r+c$ field elements, where $r$ is the rate and $c$ the capacity.
* $\mathbb F$ is the finite field type, thus $\mathbb F^L$ is a vector of $L$ elements.  
* We define input/output arguments by their type, and only add an argument'ss name when needed by our description.
* $\mathtt{Length}$ is the length type, a natural integer properly bounded counting the number field elements.
* $\mathtt{State}$ is the type of the internal state, consisting of field elements and other variables (as detailed in 2.3).


A SAFE sponge object should expose to protocol designers the following operations:

* $\mathsf{START}(\mathtt{Tag}) 
\to \mathtt{State}$: This operation initializes the internal state of the sponge, modifying up to $c/2$ field elements of the state. It's done once in the lifetime of a sponge.
* $\mathsf{ABSORB}(\mathtt{State}, \mathtt{Length}: L, \mathbb F^L: X[L])\to \mathtt{State}$: This operation adds $\lceil L/r\rceil$ blocks of $r$ field elements to the state from the array $X$, interleaving calls to the permutation as defined in 2.4.
* $\mathsf{SQUEEZE}(\mathtt{Length}: L)\to \mathbb F^L$: This operation extracts $\lceil L/r\rceil$ blocks of $r$ field elements from the state, interleaving calls to the permutation as defined in 2.4.
* $\mathsf{FINISH}(\mathtt{Length})\to\mathtt{Result}$: This operation marks the end of the sponge operation, preventing any further operation. In particular, the state is erased from memory. The result is `OK` or an error.

A sponge function is characterized by a permutation $\mathcal{P}$, a bijective mapping that maps $\mathbb{F}^n$ to itself. The general workflow of a sponge is then as follows:

1. First, a protocol initializes the sponge: $\mathsf{START}(T)$ call where $T$ is a tag computed as defined in 2.3. Note that you can also start from a precomputed state, but said state must come from a properly initialized sponge.
2. The protocol makes a chain of calls $C_1,C_2,\ldots, C_\ell$, where $\ell$ may or may not be known in advance. Each $C_i$ is either an $\mathsf{ABSORB}$ or a $\mathsf{SQUEEZE}$ call.
3. The protocol closes the sponge with a $\mathsf{FINISH}()$ call.

> Note that a call may have fewer than $r$ elements. For example, for a sponge with parameters $(r, c) = (2, 2)$, the sequence of calls may be: $\mathsf{ABSORB}$ 1 element, $\mathsf{SQUEEZE}$ 1 element,  $\mathsf{ABSORB}$ 2 elements, $\mathsf{SQUEEZE}$ 2 elements.

Important notes:


* **Non-field elements**: The API assumes that the input is (represented as) field elements, however applications may need to process other data types (for example within Fiat-Shamir transforms). It is the responsibility of users to properly encode such inputs as field elements (which is usually straightforward). Signalling the input type to avoid "collisions" between different elements of different types encoded identically is possible, but would have a prohibitive performance overhead.
* **Precomputed state:** Multiple "forks" of a sponge can be created, by storing the state after a given number of operations, and restarting from it with distinct $\mathsf{ABSORB}$ calls in distinct branches. Note that all forks must do the same calls sequence, as prescribed by the tag.  

### 2.2. Sponge state

Let $c<n$ be the number of capacity elements. The sponge state consists of the following elements:

* Permutation state $V\in \mathbb{F}^n$.
* Hasher $\mathcal{H}$, by default a SHA3-256 instance.
* Permutation $\mathcal{P}$
* Parameter tag $T$.
* Absorb position $\textsf{absorb_pos}\leq n-c$.
* Squeeze position $\textsf{squeeze_pos}\leq n-c$.


### 2.3. Sponge instance and tag



A sponge **instance** is thus only characterized by the sequence of calls and their respective lengths. For example, a simple instance could consist of 1 $\mathsf{ABSORB}$ call with 3 input elements followed by 1 $\mathsf{SQUEEZE}$ call with 1 output element. An instance doing 1 $\mathsf{ABSORB}$ call with 2 input elements (instead of 3) followed by 1 $\mathsf{SQUEEZE}$ call with 1 output element is thus a different instance.

In our API, different instances have a **different tag**, calculated as follows: a  instance is encoded as a vector $(a_1,a_2,\ldots,a_\ell, p)$ where $a_i$'s are little-endian 32-bit words which encode the sequence of calls: an $a_i$ has MSB set to 1 for an $\mathsf{ABSORB}$ call, and to 0 for a $\mathsf{SQUEEZE}$ call. The other 31 bits encode the length $L$ (number of elements absorbed or extracted).


The vector $(a_1,a_2,\ldots,a_\ell)$ is then serialized to a byte string and hashed with $\mathcal{H}$ to a 128-bit tag $T$ (truncating the hash to its first 128 bits).

Given its tag string, an instance admits an arbitrary number of **executions**, which are in addition characterized by an input $\mathcal Y\in (\mathbb F^r)^\star$. 

> Note that a mere sequence of elements is not sufficient to characterize an execution, because not all $\mathsf{ABSORB}$ calls may use the full rate. $\mathbb F^r$ elements in $\mathcal Y$ are then viewed as having zero elements in the remaining positions. 

### 2.4. Detailed API


The idea is that each call to $\mathsf{ABSORB}$ or $\mathsf{SQUEEZE}$ both:

* Reads/write the rate part of the permutation state and calls $\mathcal{P}$ when needed.
* Adds information about its own parameters to the parameter hasher.

When all calls are done, the tag hasher outputs the hash of all consumed commands. It must match the tag initially supplied to the $\mathsf{START}$ call. Otherwise, $\mathsf{FINISH}$ must fail, to reveal an error (making the wrong sequence of calls, or incorrectly computed tag).

$\mathsf{START}(T)$:
* Stores the initial tag $T$.
* Sets the permutation state to all zeros and adds $T$ to the first 128 bits of the part. If field elements are 128-bit or more, $T$ is converted to a field element. Otherwise $T$ is parsed as two or more field elements.
* Sets both absorb and squeeze positions to zero: $\textsf{absorb_pos} = \textsf{squeeze_pos} = 0$
* Set live tag bitstring $T_0$ to the empty string.

$\mathsf{ABSORB}(L, X[L])$:

* For $i = 0, 1 ,.., L-1$
	* If $\textsf{absorb_pos} == (n-c)$  then
		* Set $V = \mathcal P(V)$, to permute the state
		* Set $\textsf{absorb_pos}=0$, to restart writing at the zero offset 
	*  Write $X[i]$ to the state element at $\textsf{absorb_pos}$  // **TODO: set to Add?**
	* Do $\textsf{absorb_pos}++$
* Set $\textsf{squeeze_pos} = (n-c)$, to force a permute at the start of the next $\mathsf{SQUEEZE}$
* Append $(2^{31}+L)$ as a 32-bit little-endian unsigned integer to $T_0$

$\mathsf{SQUEEZE}(L) \to Y[L]$:

* For $i = 0, 1 ,.., L-1$
	* If $\textsf{squeeze_pos}==(n-c)$ then
		* Set $V = \mathcal P(V)$, to permute the state
		* Set $\textsf{squeeze_pos}=0$, to restart reading ouput at the zero offset 
		* Set $\textsf{absorb_pos}=0$, to start writing at the zero offset in the next $\mathsf{ABSORB}$
	* Set $Y[i]$ to the state element at position $\textsf{squeeze_pos}$
	* Do $\textsf{squeeze_pos}++$
* Append $L$ as a 32-bit little-endian unsigned integer to $T_0$
	

$\mathsf{FINISH}()$:

* If $\mathcal H(T_0)==T$ then return OK
* Else return ERROR


### 2.5. Internal API recommendation

The permutation state should not be directly manipulated as a mere vector of values. Instead, it should only expose such functions:

* `InitializeCapacity(Tag)`: Sets the first bits of the capacity elements to the tag.
* `ReadRateElement(Offset)-> FieldElement`: Reads the state element at position `Offset`
* `WriteRateElement(Offset, FieldElement)`: Writes an element to the state at position `Offset` 
* `Permute()`: Permutes the state

## 3. Functionalities

### 3.1. Hashing

The simplest way to hash $L$ elements $X=X_1, X_2,\dots, X_{L}$ is to do a single call $\mathsf{ABSORB}(L, X)$ followed by a single $\mathsf{SQUEEZE}$ call of the appropriate length. These should be preceeded by a $\mathsf{START}$ call and succeeded by a $\mathsf{FINISH}$ call.

If the $L$ elements are absorbed using more than one call -- for example, via $\mathsf{ABSORB}(1, X_1)$ followed by $\mathsf{ABSORB}(L-1, (X_2,\dots,X_{L}))$ -- then the resulting hash will be different before the sponge tag $T$ will be different and thus the initial state of the sponge will be different.

### 3.2. Merkle tree 

Consider a binary tree whose leaves and nodes are tuples from $\mathbb{F}^L$, where $L$ is a security-related parameter. The simplest case is $\mathbb{F}$ is 256-bit and $L=1$ for 128-bit security.

Each inner node with children nodes $X_1,X_2 \in \mathbb F^L$ is then obtained as follows:

* $\mathsf{START}(T)$ with $T$ the encoding of two $L$-element $\mathsf{ABSORB}$s and one $L$-element $\mathsf{SQUEEZE}$
* $\mathsf{ABSORB}(L, X_1)$ 
* $\mathsf{ABSORB}(L, X_2)$
* $Y\leftarrow \mathsf{SQUEEZE}(L)$
* $\mathsf{FINISH}()$

If $\mathsf{FINISH}$ succeeds, then $Y$ is the node value above the two nodes hashed.

### 3.3. Commitment scheme 

Consider a $M$-element commitment to three values $X_1,X_2,X_3\in \mathbb F^L$, that is, each element $X_i$ is a $L$-tuple of field elements. The commitment is then obtained as follows:

* $\mathsf{START}(T)$ with $T$ the encoding of three $L$-element $\mathsf{ABSORB}$s and one $M$-element $\mathsf{SQUEEZE}$
* $\mathsf{ABSORB}(L, X_1)$ 
* $\mathsf{ABSORB}(L, X_2)$
* $\mathsf{ABSORB}(L, X_3)$
* $Y\leftarrow \mathsf{SQUEEZE}(M)$
* $\mathsf{FINISH}()$

If $\mathsf{FINISH}$ succeeds, then $Y$ is the commitment value. Note that $L$ may be less or greater than $M$.

### 3.4. Interactive protocol

Consider the following example protocol:

1. Parties agree on the common input $Z\in\mathbb{F}^z$
2. Prover prepares and sends proof elements $\pi_1\in\mathbb{F}^{L_1}$ and $\pi_2\in\mathbb{F}^{L_2}$
3. Verifier responds with challenge $c_1\in\mathbb{F}$
4. Prover prepares and sends proof element $\pi_3\in\mathbb{F}^{L_3}$
5. Verifier responds with challenges $c_2,c_3\in\mathbb{F}$
6. Prover sends final proof $\pi_4$

The challenge generation using Fiat-Shamir  would then look as follows:

* $\mathsf{START}(T)$ with $T$ be the encoding of the following calls
* $\mathsf{ABSORB}(L_1,\pi_1)$ 
* $\mathsf{ABSORB}(L_2,\pi_2)$
* $c_1\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{ABSORB}(L_3,\pi_3)$
* $c_2\leftarrow \mathsf{SQUEEZE}(1)$
* $c_3\leftarrow \mathsf{SQUEEZE}(1)$
* $\mathsf{FINISH}()$
    
### 3.5. Authenticated encryption

Authenticated encryption with the SAFE API is a simplification of the general SpongeWrap mode (from the [Duplex paper](https://keccak.team/files/SpongeDuplex.pdf)): Encryption of $b$ blocks of data with the key $K\in\mathbb{F}^k$ and nonce $N\in\mathbb{F}^m$, where block $D_i$ consists of $L_i$ field elements, is done as follows:

* $\mathsf{START}(T)$ with $T$ be the encoding of the following calls
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
    
Then the string $(C_1+D_1)||(C_2+D_2)||\cdots ||(C_b+D_b)||S$ will be the ciphertext, where "$+$" denotes addition in $\mathbb F$. Here $t$ is the tag length, usually set to be at least 128 bits long.

This construction is the most efficient when $W_i \equiv r \mod n$, that is, all blocks fit the rate parameter of the sponge. This should be set by the protocol designer.

Decryption of $b$ blocks of data (plus $t$ extra tag elements $E_t\in\mathbb F^t$) on the key $K\in\mathbb{F}^k$ and nonce $N\in\mathbb{F}^m$, where block $E_i$ consists of $L_i$ field elements, is done as follows:

* $\mathsf{START}(T)$ with $T$ be the encoding of the following calls (thus same tag as for encryption)
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

If $S$ matches $E_t$, then the string $(E_1-C_1)||(E_2-C_2)||\cdots ||(E_l-C_l)$ is returned as plaintext.

This mode can be adapted to supported associated data (authenticated but not encrypted), in the same vein as the SpongeWrap mode.

### 3.6. Stream cipher and PRNG

A stream cipher generates a pseudo-random stream from a secret key and a not necessarily secret nonce, while a PRNG generates a pseudo-random stream from a seed. 
These can thus be instantiated with a similar sponge object to generate a pseudo-random stream $C_1, \dots, C_b$m where $C_i$ contains $L_i$ field elements: 

* $\mathsf{START}(T)$ with $T$ be the encoding of the following calls
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

## Appendices / notes

### Variable-length hashing support

TODO

### Universal hash proposal 1 (1st July 2022)  

1. In order to make the instance ligher, replace the SHA-3 call with a universal hash function call:
    * Let $X$  be a 128 bit constant, which is co-prime to $2^{128}$. 
    * The input $A=(a_0,a_1,\ldots,a_n)$ are hashed as $$
    P_h = \sum a_iX^i \bmod{2^{128}}
    $$
    * Cross-protocol collision resistance property is removed and is replaced with some weaker property.

2. In order to simplify the usage, do not distinguish between $\mathsf{ABSORB}_{l_1}()\circ \mathsf{ABSORB}_{l_2}()$ and $\mathsf{ABSORB}_{l_1+l_2}()$ calls. The same for SQUEEZE. Concretely:
    * The input values hashed to $P_h$ are total lengths of consecutive ABSORB/SQUEEZE calls rather than separate ones;
    * It is still possible to make two calls $\mathsf{ABSORB}_{l_1}()\circ \mathsf{ABSORB}_{l_2}()$ or one call $\mathsf{ABSORB}_{l_1+l_2}()$, so that they have the same effect.

3. Introduce the domain separation tag: the first input  $a_0$ to the parameter tag computation can be selected  arbitrarily by the application.  Default value is 0. It should be set to different values if the application distinguishes between two sponge calls with the same $a_1,a_2,\ldots,a_n$.