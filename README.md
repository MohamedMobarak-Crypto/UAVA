# UAVA
Raspberry pi5 implementation for UAVA authentication protocol.

We provide code implementation in C++ and in Python.

## Join Protocol and Strong Exculpability

In the preliminaries, we provided a black-box construction for any Group Signature Scheme (GSS) that has a JOIN protocol supporting strong exculpability. More precisely, the Join protocol is described as an interactive process between a user and the group manager (GM), where at the end of the protocol, the user obtains their secret signing key.

The input to the Join protocol from the user's side includes (id_i, w), where id_i is the user's identity and w is the secret component of the user's key which is not known to the GM. On the group manager's side, the input is the group manager's secret key gmsk, which is used to generate the remaining part of the user's secret key. Upon completing the protocol, the user receives their full secret key gsk_i, which is not fully known to the GM.

In our implementation, we follow the interactive JOIN protocol described by Ateniese et al. in [23], as shown in Fig. 1. The user chooses a secret value y_i and calculates h1^y_i using a public parameter h1. This value is used by the group manager to generate the rest of the key without being able to deduce y_i.
Then, the group manager chooses a secret value x_i and uses it to calculate the other part of the user’s secret key (A_i, x_i), where: A_i = (g1 / h1^y_i)^{1 / (x_i + gamma)}

By the end of the join protocol, the user has the secret key: gsk_i = (A_i, x_i, y_i), while the GM does not know y_i.

This process is analogous to our protocol design in the registration phase shown in Fig. 5 and the generic Join protocol in the preliminaries. The user generates y_i based on their biometrics. We define: z_i = h1^y_i, 
where F represents the modular exponentiation operation and indicates a one-way function.
Afterwards, the MSP generates the other part of the secret key (A_i, x_i), which is referred to as s_i in our design. Thus, at the end of the process,gsk_i = (A_i, x_i, y_i) is not fully known by the MSP, thereby providing strong exculpability. We have revised the description of the generic Join procedure in the preliminaries to reflect that it is an interactive protocol involving both the user and GM, where the user inputs a secret w not known by the GM, and ends with a secret key gsk_i not fully known by the GM.









