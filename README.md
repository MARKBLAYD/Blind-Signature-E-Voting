# Blind-Signature-E-Voting

A distributed electronic voting system that guarantees voter anonymity using **Chaum's Blind Signature** protocol. 
The system simulates a real-world election process with three independent nodes: Central Election Commission (CIK), Signing Center (CSK), and the Voter (Client).

 **Architectural Note:** To focus on the cryptographic logic and database management, inter-process communication is implemented via file exchange (JSON-formatted `.txt` files with random salt names) instead of a network protocol. 

##  System Architecture

The system consists of three independent terminal applications, each with its own database:

1.  **CIK (Central Election Commission):** Manages voters, creates elections, verifies blind labels, signs blind votes, and tallies results.
2.  **CSK (Signing Center):** Distributes cryptographic keys to voters and manages election permissions.
3.  **Client (Voter):** Registers in the system, requests blind signatures, creates anonymous votes, and views results.

##  Protocol Flow
1.  **Registration:** CIK registers a voter -> Voter generates keys -> CSK confirms keys.
2.  **Election Setup:** CIK creates an election and invites voters.
3.  **Blind Signing (Anonymity Core):** Voter blinds their secret label -> CIK signs the blind label (without seeing the label) -> Voter unblinds the signature.
4.  **Voting:** Voter attaches the valid signature to their vote and sends it to CIK.
5.  **Tallying:** CIK verifies signatures and counts votes, linking the vote to the valid signature but not to the voter's identity.

##  Tech Stack
*   **Language:** Python
*   **Database:** SQLite / PostgreSQL logic (SQL)
*   **Cryptography:** Custom implementation of Blind Signatures, RSA/key generation.
*   **IPC:** File-based JSON message passing.

##  How to Run
1. Clone the repository:
``bash
git clone https://github.com/markblayd/Blind-Signature-E-Voting.git
``
2. Set up the required directories for message exchange (e.g., shared folders or local directories depending on your setup).
3. Start the three nodes in separate terminals:
``bash
python CIK/main.py
python CSK/main.py
python Client/main.py
``
*Follow the interactive terminal menus to register voters, create elections, and vote.*

##  Challenges & Learnings
*   **Complex State Management:** Managing the lifecycle of an election across three independent databases while maintaining data consistency.
*   **Cryptography Implementation:** Implementing the math behind blind signatures and ensuring the unlinkability between the signing phase and the voting phase.
*   **Communication Bottleneck:** The file-based IPC (Inter-Process Communication) caused significant synchronization challenges. This project highlighted the critical need for real-time network protocols (TCP/UDP Sockets) in distributed systems. (See my [Kerberos Simulator](https://github.com/markblayd/Kerberos-Protocol-Simulator) for my solution to this using TCP Sockets).
