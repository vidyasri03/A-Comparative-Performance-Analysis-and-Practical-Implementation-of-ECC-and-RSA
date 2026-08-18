# A Comparative Performance Analysis and Practical Implementation of ECC and RSA

##  Project Overview

This project presents a practical implementation and comparative performance analysis of two widely used public-key cryptographic algorithms: **Elliptic Curve Cryptography (ECC)** and **RSA**.

The application provides a graphical interface for performing cryptographic operations on **text and images**, along with digital signature generation and verification. It also enables users to compare the performance of ECC and RSA based on execution time.

##  Objectives

* Implement RSA and ECC cryptographic techniques.
* Perform encryption and decryption of text data.
* Perform image encryption and decryption.
* Generate and verify digital signatures.
* Compare the computational performance of ECC and RSA.
* Provide an easy-to-use graphical interface for cryptographic operations.

##  Features

###  RSA Cryptography

* RSA key generation
* Text encryption and decryption
* Image encryption and decryption

###  ECC Cryptography

* ECC key generation
* Text encryption and decryption
* Image encryption and decryption

###  Digital Signatures

* Generate digital signatures
* Verify signatures
* Demonstrate message authenticity and integrity

###  Performance Analysis

* Measures execution time for cryptographic operations
* Provides comparative analysis between ECC and RSA
* Helps visualize the computational differences between the two algorithms

### Graphical User Interface

The application is developed using **PyQt5** and provides separate interfaces for text and image encryption operations.

##  Technologies Used

* **Python 3**
* **PyQt5** – Graphical User Interface
* **PyCryptodome** – RSA and cryptographic operations
* **ECDSA** – Elliptic Curve Digital Signature Algorithm
* **Matplotlib** – Performance visualization
* **NumPy** – Numerical operations
* **Pillow (PIL)** – Image processing

##  System Workflow

```text
                    ┌─────────────────────┐
                    │      CryptoApp      │
                    │      PyQt5 GUI      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
       ┌──────▼──────┐                   ┌──────▼──────┐
       │    Text     │                   │    Image    │
       │ Operations  │                   │ Operations  │
       └──────┬──────┘                   └──────┬──────┘
              │                                 │
       ┌──────┴──────┐                   ┌──────┴──────┐
       │             │                   │             │
    RSA / ECC     Sign / Verify       RSA / ECC    Encrypt /
       │             │                   │             │
       └─────────────┴───────────────────┴─────────────┘
                               │
                       ┌───────▼────────┐
                       │   Performance  │
                       │    Analysis    │
                       └────────────────┘
```

## Project Structure

```text
├── change_final.py
├── background.jpeg
├── background.png
├── crypto.gif
├── decrypt.png
├── decrypted_image.png
└── README.md
```

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/vidyasri03/A-Comparative-Performance-Analysis-and-Practical-Implementation-of-ECC-and-RSA.git
```

### 2. Open the project directory

```bash
cd A-Comparative-Performance-Analysis-and-Practical-Implementation-of-ECC-and-RSA
```

### 3. Install the required dependencies

```bash
pip install PyQt5 matplotlib ecdsa pycryptodome Pillow numpy
```

### 4. Run the application

```bash
python change_final.py
```

The **CryptoApp** graphical interface will launch.

##  Demo

The project includes a demonstration GIF showing the cryptographic application and its interface.

![CryptoApp Demo](crypto.gif)

## 🔍 ECC vs RSA

| Feature                  | ECC                                       | RSA                                            |
| ------------------------ | ----------------------------------------- | ---------------------------------------------- |
| Key Size                 | Smaller                                   | Larger                                         |
| Security per Key Size    | High                                      | Lower compared with ECC                        |
| Computational Efficiency | Generally efficient with smaller keys     | Requires larger keys                           |
| Resource Usage           | Lower for comparable security levels      | Higher for comparable security levels          |
| Common Applications      | Modern secure systems, digital signatures | Encryption, digital signatures, legacy systems |

##  Performance Analysis

The application measures the execution time of cryptographic operations to provide a practical comparison between ECC and RSA.

The analysis focuses on:

* Key generation time
* Encryption/decryption performance
* Digital signature operations
* Computational overhead

The results can be used to understand the practical trade-offs between the two public-key cryptographic approaches.

##  Learning Outcomes

Through this project, the following concepts were explored:

* Public-key cryptography
* RSA encryption
* Elliptic Curve Cryptography
* Digital signatures
* Message integrity and authentication
* Image encryption
* GUI-based cryptographic applications
* Cryptographic performance benchmarking

##  Author

**Vidya Sri K.**

B.Tech – Computer Science and Engineering | 2026 Graduate
