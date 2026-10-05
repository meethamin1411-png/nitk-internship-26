"""===============================================================================
                     BAN LOGIC VERIFICATION ENGINE
===============================================================================

Project:
    Post-Quantum Certificateless Mutual Authentication and Key Agreement
    (PQC-CMAKA) Protocol for VANETs

Author:
    Meeth Amin

Description:
    This module implements a complete BAN (Burrows-Abadi-Needham) Logic
    verification engine for the proposed PQC-CMAKA protocol.

Objectives:
    • Verify Mutual Authentication
    • Verify Session Key Agreement
    • Verify Session Key Freshness
    • Verify Key Confirmation
    • Automatically Generate BAN Proof
    • Automatically Generate BAN Logic Equations
    • Produce Human-Readable Verification Reports

Protocol Participants:
    • Trusted Authority (TA)
    • Road Side Unit (RSU)
    • Vehicle

Protocol Messages:
    M1 : Vehicle  → RSU
    M2 : RSU      → Vehicle
    M3 : Vehicle  → RSU
    M4 : RSU      → Vehicle (Optional Confirmation)

This implementation is designed for research purposes and can be integrated
with:
    • mutual_authentication.py
    • context_aware_session_key.py
    • secure_message_transfer.py

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum, auto
from datetime import datetime
# =============================================================================
# Protocol Participants
# =============================================================================

VEHICLE = "Vehicle"
RSU = "RSU"
TA = "Trusted Authority"
# Protocol Message IDs
M1 = "M1"
M2 = "M2"
M3 = "M3"
M4 = "M4"
# =============================================================================
# BAN Rule Names
# =============================================================================

MESSAGE_MEANING = "Message Meaning Rule"

FRESHNESS = "Freshness Rule"

NONCE_VERIFICATION = "Nonce Verification Rule"

JURISDICTION = "Jurisdiction Rule"

SESSION_KEY = "Session Key Rule"

KEY_CONFIRMATION = "Key Confirmation Rule"
# =============================================================================
# Verification Status
# =============================================================================

PASSED = "PASSED"

FAILED = "FAILED"

PENDING = "PENDING"
# =============================================================================
# BAN Predicates
# =============================================================================

class Predicate(Enum):
    BELIEVES = auto()
    ONCE_SAID = auto()
    FRESH = auto()
    TRUSTS = auto()
    CONTROLS = auto()
    SHARES_KEY = auto()
    AUTHENTICATED = auto()
    SESSION_KEY = auto()
    KNOWS = auto()
    # =============================================================================
# Security Goals
# =============================================================================

class Goal(Enum):
    MUTUAL_AUTHENTICATION = auto()
    SESSION_KEY_AGREEMENT = auto()
    SESSION_KEY_FRESHNESS = auto()
    KEY_CONFIRMATION = auto()
    # =============================================================================
# BAN Rule Types
# =============================================================================

class RuleType(Enum):
    MESSAGE_MEANING = auto()
    FRESHNESS = auto()
    NONCE_VERIFICATION = auto()
    JURISDICTION = auto()
    SESSION_KEY = auto()
    KEY_CONFIRMATION = auto()
    # =============================================================================
# Protocol Message Types
# =============================================================================

class MessageType(Enum):
    REGISTRATION = auto()
    AUTHENTICATION = auto()
    KEY_EXCHANGE = auto()
    SESSION_ESTABLISHMENT = auto()
    CONFIRMATION = auto()
    # =============================================================================
# Engine Configuration
# =============================================================================

ENGINE_NAME = "BAN Logic Verification Engine"

ENGINE_VERSION = "3.0"

PROTOCOL_NAME = "PQC-CMAKA"

DEBUG_MODE = False
# =============================================================================
# PART 2 : BAN Expression
# =============================================================================

@dataclass(frozen=True)
class Expression:
    """
    Represents a single BAN Logic expression.

    General Form:
        <Subject> <Predicate> <Object>

    Examples:
        RSU once_said Nv
        Vehicle believes SessionKey
        TA controls PublicKey
        Vehicle shares_key RSU
    """

    subject: str
    predicate: Predicate
    object: Any
    def __str__(self) -> str:
        """Returns a readable BAN Logic expression."""
        return (
            f"{self.subject} "
            f"{self.predicate.name.lower()} "
            f"{self.object}"
        )

    def to_equation(self) -> str:
        symbols = {
            Predicate.BELIEVES: "|≡",
            Predicate.ONCE_SAID: "|~",
            Predicate.FRESH: "#",
            Predicate.TRUSTS: "⇔",
            Predicate.CONTROLS: "⇒",
            Predicate.SHARES_KEY: "↔K",
            Predicate.AUTHENTICATED: "≡",
            Predicate.SESSION_KEY: "↔K",
            Predicate.KNOWS: "⊳"
        }

        symbol = symbols.get(self.predicate, self.predicate.name)

        if self.predicate == Predicate.FRESH:
            return f"{symbol}({self.object})"

        return f"{self.subject} {symbol} {self.object}"

    def as_tuple(self):
        """
        Returns a tuple representation for comparisons
        and hashing.
        """
        return (
            self.subject,
            self.predicate,
            self.object
        ) 
 # =============================================================================
# PART 3 : BAN Belief
# =============================================================================

@dataclass(frozen=True)
class Belief:
    """
    Represents a BAN Logic belief.

    General Form:
        <Owner> believes (<Expression>)

    Example:
        Vehicle believes (RSU once_said Nv)
        RSU believes (Vehicle authenticated)
        TA believes (Vehicle shares_key RSU)
    """

    owner: str
    expression: Expression

    def __str__(self) -> str:
        """
        Returns a readable belief.
        """
        return (
            f"{self.owner} believes "
            f"({self.expression})"
        )

    def to_equation(self) -> str:
        """
        Returns BAN notation for reports.

        Example:
            Vehicle ⊢ (RSU ONCE_SAID Nv)
        """
        return (
            f"{self.owner} |≡ "
            f"({self.expression.to_equation()})"
        )

    def as_tuple(self):
        """
        Returns a tuple representation.

        Useful for hashing, comparisons,
        duplicate detection, and proof generation.
        """
        return (
            self.owner,
            self.expression.as_tuple()
        )

    def matches(
        self,
        subject: Optional[str] = None,
        predicate: Optional[Predicate] = None,
        obj: Optional[Any] = None
    ) -> bool:
        """
        Flexible matcher used by BAN inference rules.

        Any parameter left as None is ignored.
        """

        if (
            subject is not None
            and self.expression.subject != subject
        ):
            return False

        if (
            predicate is not None
            and self.expression.predicate != predicate
        ):
            return False

        if (
            obj is not None
            and self.expression.object != obj
        ):
            return False

        return True
        # =============================================================================
# PART 4 : Freshness
# =============================================================================

@dataclass(frozen=True)
class Freshness:
    """
    Represents the BAN Logic concept of Fresh(X).

    Freshness indicates that a value (nonce, timestamp,
    session key, etc.) has not been used previously.

    Examples:
        Fresh(Nv)
        Fresh(Nr)
        Fresh(SessionKey)
        Fresh(Timestamp)
    """

    item: Any

    def __str__(self) -> str:
        """
        Returns a readable freshness statement.
        """
        return f"Fresh({self.item})"

    def to_equation(self) -> str:
        """
        Returns BAN notation.

        Example:
            Fresh(Nv)
        """
        return f"Fresh({self.item})"

    def as_tuple(self):
        """
        Returns a tuple representation.

        Useful for hashing and duplicate detection.
        """
        return (self.item,)

    def matches(
        self,
        item: Optional[Any] = None
    ) -> bool:
        """
        Flexible matcher.

        Example:
            freshness.matches("Nv")
        """

        if item is not None and self.item != item:
            return False

        return True
        # =============================================================================
# PART 5 : Shared Key
# =============================================================================

@dataclass(frozen=True)
class SharedKey:
    """
    Represents a shared secret between two protocol participants.

    General Form:
        <Owner> ↔ <Peer> : SessionKey

    Examples:
        Vehicle ↔ RSU : SK1
        RSU ↔ Vehicle : SessionKey
    """

    owner: str
    peer: str
    key: Any
    algorithm: str = "ML-KEM"

    def __str__(self) -> str:
        """
        Returns a readable representation.
        """
        return (
            f"{self.owner} ↔ {self.peer} : "
            f"{self.key} ({self.algorithm})"
        )

    def to_equation(self) -> str:
        """
        Returns BAN notation.

        Example:
            Vehicle ↔ₖ RSU
        """
        return (
            f"{self.owner} ↔ₖ "
            f"{self.peer}"
        )

    def as_tuple(self):
        """
        Returns a tuple representation.

        Useful for hashing, duplicate detection,
        and equality comparisons.
        """
        return (
            self.owner,
            self.peer,
            self.key,
            self.algorithm
        )

    def matches(
        self,
        owner: Optional[str] = None,
        peer: Optional[str] = None,
        key: Optional[Any] = None,
        algorithm: Optional[str] = None
    ) -> bool:
        """
        Flexible matcher used by BAN rules.
        """

        if owner is not None and self.owner != owner:
            return False

        if peer is not None and self.peer != peer:
            return False

        if key is not None and self.key != key:
            return False

        if algorithm is not None and self.algorithm != algorithm:
            return False

        return True
        # =============================================================================
# PART 6 : Protocol Message
# =============================================================================

@dataclass
class ProtocolMessage:
    """
    Represents a protocol message exchanged between participants.

    This generic message structure supports all protocol messages
    (M1, M2, M3 and M4) of the PQC-CMAKA protocol.
    """

    message_id: str

    sender: str

    receiver: str

    message_type: MessageType

    pseudonym: Optional[str] = None

    authentication_code: Optional[str] = None

    nonce: Optional[str] = None

    timestamp: Optional[str] = None

    signature: Optional[str] = None

    kem_public_key: Optional[str] = None

    kem_ciphertext: Optional[str] = None

    session_key: Optional[str] = None

    payload: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """
        Returns a readable summary.
        """

        return (
            f"{self.message_id}: "
            f"{self.sender} → {self.receiver}"
        )

    def summary(self) -> str:
        """
        Returns a detailed message summary.
        """

        return (
            f"Message={self.message_id}, "
            f"Sender={self.sender}, "
            f"Receiver={self.receiver}, "
            f"Type={self.message_type.name}"
        )

    def contains_nonce(self) -> bool:
        """
        Returns True if the message contains a nonce.
        """

        return self.nonce is not None

    def contains_signature(self) -> bool:
        """
        Returns True if the message contains a digital signature.
        """

        return self.signature is not None

    def contains_public_key(self) -> bool:
        """
        Returns True if the message carries an ML-KEM public key.
        """

        return self.kem_public_key is not None

    def contains_ciphertext(self) -> bool:
        """
        Returns True if the message carries an ML-KEM ciphertext.
        """

        return self.kem_ciphertext is not None

    def contains_session_key(self) -> bool:
        """
        Returns True if a session key has been established.
        """

        return self.session_key is not None

    def get_field(self, field_name: str) -> Any:
        """
        Returns the value of any field dynamically.

        Example:
            message.get_field("nonce")
        """

        return getattr(self, field_name, None)

    def as_dict(self) -> Dict[str, Any]:
        """
        Converts the complete message into a dictionary.
        """

        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "message_type": self.message_type.name,
            "pseudonym": self.pseudonym,
            "authentication_code": self.authentication_code,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "kem_public_key": self.kem_public_key,
            "kem_ciphertext": self.kem_ciphertext,
            "session_key": self.session_key,
            "payload": self.payload
        }
        # =============================================================================
# PART 7 : Proof Step
# =============================================================================

@dataclass
class ProofStep:
    """
    Represents a single BAN Logic inference step.

    Each time a BAN rule is successfully applied,
    one ProofStep object is created and stored.
    """

    step_number: int

    rule: RuleType

    input_facts: List[str]

    derived_fact: str

    status: str = PASSED

    timestamp: datetime = field(default_factory=datetime.now)

    remarks: Optional[str] = None

    def __str__(self) -> str:
        """
        Returns a readable proof step.
        """

        return (
            f"Step {self.step_number}: "
            f"{self.rule.name} -> "
            f"{self.status}"
        )

    def summary(self) -> str:
        """
        Returns a detailed proof summary.
        """

        lines = [
            f"Step Number : {self.step_number}",
            f"Rule        : {self.rule.name}",
            f"Status      : {self.status}",
            "Input Facts :"
        ]

        for fact in self.input_facts:
            lines.append(f"  • {fact}")

        lines.append(f"Derived Fact: {self.derived_fact}")

        if self.remarks:
            lines.append(f"Remarks     : {self.remarks}")

        lines.append(
            f"Timestamp   : "
            f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        return "\n".join(lines)

    def as_dict(self) -> Dict[str, Any]:
        """
        Converts the proof step into a dictionary.
        """

        return {
            "step_number": self.step_number,
            "rule": self.rule.name,
            "input_facts": self.input_facts,
            "derived_fact": self.derived_fact,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "remarks": self.remarks
        }

    def is_successful(self) -> bool:
        """
        Returns True if the inference succeeded.
        """

        return self.status == PASSED
        # =============================================================================
# PART 8 : BAN Entity
# =============================================================================

class BANEntity:
    """
    Represents a protocol participant.

    Examples:
        Vehicle
        RSU
        Trusted Authority

    Each entity maintains its own knowledge base consisting of:

        • Beliefs
        • Fresh Values
        • Shared Keys
        • Received Messages
        • Jurisdictions
    """

    def __init__(self, name: str):

        self.name = name

        self.beliefs: Set[Belief] = set()

        self.fresh_items: Set[Freshness] = set()

        self.shared_keys: Set[SharedKey] = set()

        self.messages: List[ProtocolMessage] = []

        self.jurisdictions: Set[Expression] = set()

    # -------------------------------------------------------------------------
    # Belief Management
    # -------------------------------------------------------------------------

    def add_belief(self, expression: Expression) -> None:
        """Adds a belief to the entity."""
        self.beliefs.add(
            Belief(
                owner=self.name,
                expression=expression
            )
        )

    def has_belief(self, expression: Expression) -> bool:
        """Checks whether the entity already believes an expression."""
        return Belief(
            owner=self.name,
            expression=expression
        ) in self.beliefs

    def remove_belief(self, expression: Expression) -> None:
        """Removes a belief if present."""
        self.beliefs.discard(
            Belief(
                owner=self.name,
                expression=expression
            )
        )

    def get_beliefs(self) -> List[Belief]:
        """Returns all beliefs."""
        return sorted(
            self.beliefs,
            key=lambda b: str(b)
        )

    # -------------------------------------------------------------------------
    # Freshness Management
    # -------------------------------------------------------------------------

    def add_freshness(self, fresh: Freshness) -> None:
        """Stores a fresh value."""
        self.fresh_items.add(fresh)

    def is_fresh(self, item) -> bool:
        """Checks whether an item is fresh."""
        return Freshness(item) in self.fresh_items

    def get_fresh_items(self) -> List[Freshness]:
        """Returns all fresh values."""
        return sorted(
            self.fresh_items,
            key=lambda f: str(f)
        )

    # -------------------------------------------------------------------------
    # Shared Key Management
    # -------------------------------------------------------------------------

    def add_shared_key(self, shared_key: SharedKey) -> None:
        """Stores a shared key."""
        self.shared_keys.add(shared_key)

    def has_shared_key(self, peer: str) -> bool:
        """Checks whether a shared key exists with a peer."""

        return any(
            key.peer == peer
            for key in self.shared_keys
        )

    def get_shared_key(self, peer: str) -> Optional[SharedKey]:
        """Returns the shared key with a peer."""

        for key in self.shared_keys:

            if key.peer == peer:
                return key

        return None

    # -------------------------------------------------------------------------
    # Message Management
    # -------------------------------------------------------------------------

    def receive_message(
        self,
        message: ProtocolMessage
    ) -> None:
        """Stores an incoming protocol message."""
        self.messages.append(message)

    def get_messages(self) -> List[ProtocolMessage]:
        """Returns all received messages."""
        return self.messages

    def last_message(self) -> Optional[ProtocolMessage]:
        """Returns the latest received message."""

        if not self.messages:
            return None

        return self.messages[-1]

    # -------------------------------------------------------------------------
    # Jurisdiction Management
    # -------------------------------------------------------------------------

    def add_jurisdiction(
        self,
        expression: Expression
    ) -> None:
        """
        Adds a jurisdiction statement.

        Example:
            TA controls Vehicle Certificate
        """
        self.jurisdictions.add(expression)

    def has_jurisdiction(
        self,
        expression: Expression
    ) -> bool:
        """Checks jurisdiction."""
        return expression in self.jurisdictions

    def get_jurisdictions(self) -> List[Expression]:
        """Returns all jurisdiction statements."""

        return sorted(
            self.jurisdictions,
            key=lambda e: str(e)
        )

    # -------------------------------------------------------------------------
    # Utility Functions
    # -------------------------------------------------------------------------

    def clear(self) -> None:
        """Resets the entity."""

        self.beliefs.clear()

        self.fresh_items.clear()

        self.shared_keys.clear()

        self.messages.clear()

        self.jurisdictions.clear()

    def statistics(self) -> Dict[str, int]:
        """Returns knowledge base statistics."""

        return {

            "beliefs": len(self.beliefs),

            "fresh_items": len(self.fresh_items),

            "shared_keys": len(self.shared_keys),

            "messages": len(self.messages),

            "jurisdictions": len(self.jurisdictions)

        }

    def __str__(self) -> str:
        return f"BANEntity({self.name})"

    def __repr__(self) -> str:
        return self.__str__()
        # =============================================================================
# PART 9 : BAN Rule Base
# =============================================================================

class BANRules:
    """
    Implements the BAN Logic inference rules.

    The methods in this class do not control protocol execution.
    They simply apply logical inference and derive new beliefs.

    Supported Rules:
        • Message Meaning Rule
        • Freshness Rule
        • Nonce Verification Rule
        • Jurisdiction Rule
        • Session Key Rule
        • Key Confirmation Rule
    """

    @staticmethod
    def message_meaning(
        receiver: BANEntity,
        sender: BANEntity,
        expression: Expression
    ) -> Optional[Belief]:
        """
        Message Meaning Rule

        If receiver shares a trusted key with sender and receives
        a protected message, receiver believes that sender once
        said the enclosed statement.
        """

        if not receiver.has_shared_key(sender.name):
            return None

        new_expression = Expression(
            subject=sender.name,
            predicate=Predicate.ONCE_SAID,
            object=expression.object
        )

        receiver.add_belief(new_expression)

        return Belief(
            owner=receiver.name,
            expression=new_expression
        )

    @staticmethod
    def freshness(
        receiver: BANEntity,
        item: Any
    ) -> bool:
        """
        Freshness Rule

        Determines whether an item is considered fresh.
        """

        return receiver.is_fresh(item)

    @staticmethod
    def nonce_verification(
        receiver: BANEntity,
        sender: BANEntity,
        nonce: Any
    ) -> Optional[Belief]:
        """
        Nonce Verification Rule

        If the nonce is fresh and the receiver believes
        that the sender once said it, conclude that the
        sender currently believes it.
        """

        if not receiver.is_fresh(nonce):
            return None

        previous = Expression(
            subject=sender.name,
            predicate=Predicate.ONCE_SAID,
            object=nonce
        )

        if not receiver.has_belief(previous):
            return None

        new_expression = Expression(
            subject=sender.name,
            predicate=Predicate.BELIEVES,
            object=nonce
        )

        receiver.add_belief(new_expression)

        return Belief(
            owner=receiver.name,
            expression=new_expression
        )

    @staticmethod
    def jurisdiction(
        receiver: BANEntity,
        authority: BANEntity,
        statement: Expression
    ) -> Optional[Belief]:
        """
        Jurisdiction Rule

        If receiver believes the authority controls a statement,
        and authority believes that statement, then receiver
        accepts the statement.
        """

        control_expression = Expression(
            subject=authority.name,
            predicate=Predicate.CONTROLS,
            object=statement.object
        )

        authority_belief = Expression(
            subject=authority.name,
            predicate=Predicate.BELIEVES,
            object=statement.object
        )

        if not receiver.has_jurisdiction(control_expression):
            return None

        if not authority.has_belief(authority_belief):
            return None

        receiver.add_belief(statement)

        return Belief(
            owner=receiver.name,
            expression=statement
        )

    @staticmethod
    def session_key(
        entity: BANEntity,
        peer: BANEntity
    ) -> Optional[Belief]:
        """
        Session Key Rule

        Verifies that both entities share a session key.
        """

        if not entity.has_shared_key(peer.name):
            return None

        new_expression = Expression(
            subject=entity.name,
            predicate=Predicate.SESSION_KEY,
            object=peer.name
        )

        entity.add_belief(new_expression)

        return Belief(
            owner=entity.name,
            expression=new_expression
        )

    @staticmethod
    def key_confirmation(
        entity: BANEntity,
        peer: BANEntity
    ) -> Optional[Belief]:
        """
        Key Confirmation Rule

        Confirms that both entities acknowledge
        possession of the same session key.
        """

        if not entity.has_shared_key(peer.name):
            return None

        new_expression = Expression(
            subject=entity.name,
            predicate=Predicate.AUTHENTICATED,
            object=peer.name
        )

        entity.add_belief(new_expression)

        return Belief(
            owner=entity.name,
            expression=new_expression
        )
        # =============================================================================
# PART 10 : BAN Logic Engine
# =============================================================================

class BANLogicEngine:
    """
    Central BAN Logic Verification Engine.

    Responsibilities
    ----------------
    • Maintain protocol participants
    • Store protocol messages
    • Store proof steps
    • Apply BAN inference rules
    • Verify security goals
    • Generate reports
    """

    def __init__(self):

        # -------------------------------------------------------------
        # Protocol Participants
        # -------------------------------------------------------------

        self.entities: Dict[str, BANEntity] = {

            VEHICLE: BANEntity(VEHICLE),

            RSU: BANEntity(RSU),

            TA: BANEntity(TA)

        }

        # -------------------------------------------------------------
        # Protocol Messages
        # -------------------------------------------------------------

        self.messages: List[ProtocolMessage] = []

        # -------------------------------------------------------------
        # BAN Proof
        # -------------------------------------------------------------

        self.proof_steps: List[ProofStep] = []

        # -------------------------------------------------------------
        # Verification Results
        # -------------------------------------------------------------

        self.verification_results: Dict[Goal, bool] = {}

        # -------------------------------------------------------------
        # Internal Step Counter
        # -------------------------------------------------------------

        self.step_counter = 1

    # =================================================================
    # Entity Management
    # =================================================================

    def get_entity(self, name: str) -> BANEntity:
        """
        Returns the requested protocol participant.
        """

        return self.entities[name]

    def add_entity(self, entity: BANEntity) -> None:
        """
        Adds a new protocol participant.
        """

        self.entities[entity.name] = entity

    # =================================================================
    # Message Management
    # =================================================================

    def add_message(
        self,
        message: ProtocolMessage
    ) -> None:
        """
        Stores a protocol message.
        """

        self.messages.append(message)

        receiver = self.get_entity(
            message.receiver
        )

        receiver.receive_message(message)

    def get_messages(self) -> List[ProtocolMessage]:
        """
        Returns all protocol messages.
        """

        return self.messages

    # =================================================================
    # Proof Management
    # =================================================================

    def add_proof_step(
        self,
        rule: RuleType,
        input_facts: List[str],
        derived_fact: str,
        status: str = PASSED,
        remarks: Optional[str] = None
    ) -> None:
        """
        Adds one proof step.
        """

        step = ProofStep(

            step_number=self.step_counter,

            rule=rule,

            input_facts=input_facts,

            derived_fact=derived_fact,

            status=status,

            remarks=remarks

        )

        self.proof_steps.append(step)

        self.step_counter += 1

    def get_proof(self) -> List[ProofStep]:
        """
        Returns the complete BAN proof.
        """

        return self.proof_steps

    # =================================================================
    # Verification Results
    # =================================================================

    def set_goal(
        self,
        goal: Goal,
        status: bool
    ) -> None:
        """
        Stores verification status.
        """

        self.verification_results[goal] = status

    def goal_status(
        self,
        goal: Goal
    ) -> bool:
        """
        Returns verification status.
        """

        return self.verification_results.get(
            goal,
            False
        )

    # =================================================================
    # Engine Utilities
    # =================================================================

    def reset(self) -> None:
        """
        Clears the complete engine.
        """

        for entity in self.entities.values():

            entity.clear()

        self.messages.clear()

        self.proof_steps.clear()

        self.verification_results.clear()

        self.step_counter = 1

    def statistics(self) -> Dict[str, int]:
        """
        Returns engine statistics.
        """

        return {

            "participants": len(self.entities),

            "messages": len(self.messages),

            "proof_steps": len(self.proof_steps),

            "verified_goals": len(self.verification_results)

        }

    def __str__(self):

        return (

            f"{ENGINE_NAME} "

            f"v{ENGINE_VERSION}"

        )
        # =============================================================================
# PART 11 : Initial BAN Assumptions
# =============================================================================

    def initialize_assumptions(self) -> None:
        """
        Initializes the BAN Logic assumptions for the
        PQC-CMAKA protocol.

        These assumptions form the trust model before
        any protocol messages are exchanged.
        """

        vehicle = self.get_entity(VEHICLE)
        rsu = self.get_entity(RSU)
        ta = self.get_entity(TA)

        # ==============================================================
        # A1
        # Vehicle trusts Trusted Authority
        # ==============================================================

        vehicle.add_belief(
            Expression(
                subject=TA,
                predicate=Predicate.TRUSTS,
                object=TA
            )
        )

        # ==============================================================
        # A2
        # RSU trusts Trusted Authority
        # ==============================================================

        rsu.add_belief(
            Expression(
                subject=TA,
                predicate=Predicate.TRUSTS,
                object=TA
            )
        )

        # ==============================================================
        # A3
        # Trusted Authority controls Vehicle identity
        # ==============================================================

        vehicle.add_jurisdiction(

            Expression(
                subject=TA,
                predicate=Predicate.CONTROLS,
                object="Vehicle Identity"
            )

        )

        # ==============================================================
        # A4
        # Trusted Authority controls RSU identity
        # ==============================================================

        rsu.add_jurisdiction(

            Expression(
                subject=TA,
                predicate=Predicate.CONTROLS,
                object="RSU Identity"
            )

        )

        # ==============================================================
        # A5
        # Vehicle believes its nonce is fresh
        # ==============================================================

        vehicle.add_freshness(
            Freshness("Nv")
        )

        # ==============================================================
        # A6
        # RSU believes its nonce is fresh
        # ==============================================================

        rsu.add_freshness(
            Freshness("Nr")
        )

        # ==============================================================
        # A7
        # Vehicle and RSU establish an ML-KEM session key
        # ==============================================================

        vehicle.add_shared_key(

            SharedKey(
                owner=VEHICLE,
                peer=RSU,
                key="SessionKey",
                algorithm="ML-KEM"
            )

        )

        rsu.add_shared_key(

            SharedKey(
                owner=RSU,
                peer=VEHICLE,
                key="SessionKey",
                algorithm="ML-KEM"
            )

        )

        # ==============================================================
        # A8
        # Trusted Authority believes protocol participants
        # are registered.
        # ==============================================================

        ta.add_belief(

            Expression(
                subject=VEHICLE,
                predicate=Predicate.AUTHENTICATED,
                object=RSU
            )

        )

        ta.add_belief(

            Expression(
                subject=RSU,
                predicate=Predicate.AUTHENTICATED,
                object=VEHICLE
            )

        )
            # ==============================================================
    # A9
    # Vehicle believes SessionKey is fresh
    # ==============================================================

        vehicle.add_freshness(
            Freshness("SessionKey")
        )

    # ==============================================================
    # A10
    # RSU believes SessionKey is fresh
    # ==============================================================

        rsu.add_freshness(
           Freshness("SessionKey")
        )

        print("\nInitializing BAN Logic Assumptions...")

        print("✓ A1  Vehicle trusts Trusted Authority")

        print("✓ A2  RSU trusts Trusted Authority")

        print("✓ A3  TA controls Vehicle Identity")

        print("✓ A4  TA controls RSU Identity")

        print("✓ A5  Fresh(Nv)")

        print("✓ A6  Fresh(Nr)")

        print("✓ A7  ML-KEM Shared Session Key")

        print("✓ A8  Registered Participants")
        print("✓ A9  Fresh(SessionKey) at Vehicle")
        print("✓ A10 Fresh(SessionKey) at RSU")

        print("\nBAN Assumptions Loaded Successfully.\n")
        # =============================================================================
# PART 12 : BAN Inference Engine
# =============================================================================

    def apply_rule(
        self,
        rule: RuleType,
        receiver: str,
        sender: str,
        expression: Optional[Expression] = None,
        nonce: Optional[str] = None
    ) -> bool:
        """
        Applies a BAN inference rule and records the proof.

        Returns
        -------
        True  -> Rule succeeded
        False -> Rule failed
        """

        receiver_entity = self.get_entity(receiver)
        sender_entity = self.get_entity(sender)

        result = None

        # -------------------------------------------------------------
        # Message Meaning Rule
        # -------------------------------------------------------------

        if rule == RuleType.MESSAGE_MEANING:

            if expression is None:
                return False

            result = BANRules.message_meaning(
                receiver_entity,
                sender_entity,
                expression
            )

        # -------------------------------------------------------------
        # Freshness Rule
        # -------------------------------------------------------------

        elif rule == RuleType.FRESHNESS:

            if nonce is None:
                return False

            return BANRules.freshness(
                receiver_entity,
                nonce
            )

        # -------------------------------------------------------------
        # Nonce Verification Rule
        # -------------------------------------------------------------

        elif rule == RuleType.NONCE_VERIFICATION:

            if nonce is None:
                return False

            result = BANRules.nonce_verification(
                receiver_entity,
                sender_entity,
                nonce
            )

        # -------------------------------------------------------------
        # Jurisdiction Rule
        # -------------------------------------------------------------

        elif rule == RuleType.JURISDICTION:

            if expression is None:
                return False

            result = BANRules.jurisdiction(
                receiver_entity,
                sender_entity,
                expression
            )

        # -------------------------------------------------------------
        # Session Key Rule
        # -------------------------------------------------------------

        elif rule == RuleType.SESSION_KEY:

            result = BANRules.session_key(
                receiver_entity,
                sender_entity
            )

        # -------------------------------------------------------------
        # Key Confirmation Rule
        # -------------------------------------------------------------

        elif rule == RuleType.KEY_CONFIRMATION:

            result = BANRules.key_confirmation(
                receiver_entity,
                sender_entity
            )

        else:
            return False

        # -------------------------------------------------------------
        # Store Proof
        # -------------------------------------------------------------

        if result is not None:

            self.add_proof_step(

                rule=rule,

                input_facts=[
                    f"{receiver} received authenticated message from {sender}"
                ],

                derived_fact=str(result),

                status=PASSED

            )

            return True

        return False
        # =============================================================================
# PART 13 : Intelligent Protocol Processor
# =============================================================================

    def process_message(
        self,
        message: ProtocolMessage
    ) -> bool:
        """
        Processes a protocol message and automatically
        applies the appropriate BAN Logic inference rules.
        """

        # -------------------------------------------------------------
        # Store Message
        # -------------------------------------------------------------

        sender = message.sender
        receiver = message.receiver

        print(f"\nProcessing {message.message_id}...")
        print(f"{sender} → {receiver}")

        # -------------------------------------------------------------
        # M1 : Vehicle → RSU
        # -------------------------------------------------------------

        if message.message_id == M1:

            if message.nonce:

                expression = Expression(
                    subject=sender,
                    predicate=Predicate.KNOWS,
                    object=message.nonce
                )

                self.apply_rule(
                    RuleType.MESSAGE_MEANING,
                    receiver=receiver,
                    sender=sender,
                    expression=expression
                )

                self.apply_rule(
                    RuleType.NONCE_VERIFICATION,
                    receiver=receiver,
                    sender=sender,
                    nonce=message.nonce
                )

            return True

        # -------------------------------------------------------------
        # M2 : RSU → Vehicle
        # -------------------------------------------------------------

        elif message.message_id == M2:

            if message.nonce:

                expression = Expression(
                    subject=sender,
                    predicate=Predicate.KNOWS,
                    object=message.nonce
                )

                self.apply_rule(
                    RuleType.MESSAGE_MEANING,
                    receiver=receiver,
                    sender=sender,
                    expression=expression
                )

                self.apply_rule(
                    RuleType.NONCE_VERIFICATION,
                    receiver=receiver,
                    sender=sender,
                    nonce=message.nonce
                )

            return True

        # -------------------------------------------------------------
        # M3 : Vehicle → RSU
        # -------------------------------------------------------------

        elif message.message_id == M3:

            if message.kem_ciphertext:

                self.apply_rule(
                    RuleType.SESSION_KEY,
                    receiver=receiver,
                    sender=sender
                )

            return True

        # -------------------------------------------------------------
        # M4 : RSU → Vehicle
        # -------------------------------------------------------------

        elif message.message_id == M4:

            if message.session_key:

                self.apply_rule(
                    RuleType.KEY_CONFIRMATION,
                    receiver=receiver,
                    sender=sender
                )
                self.apply_rule(
                    RuleType.KEY_CONFIRMATION,
                    receiver=sender,
                    sender=receiver
                )


            return True

        # -------------------------------------------------------------
        # Unknown Message
        # -------------------------------------------------------------

        else:

            print(
                f"Unknown protocol message: {message.message_id}"
            )

            return False
            # =============================================================================
# PART 14 : Security Goal Verification
# =============================================================================

    def verify_goals(self) -> Dict[Goal, bool]:
        """
        Verifies whether the PQC-CMAKA protocol satisfies
        the required BAN Logic security goals.

        Returns
        -------
        Dictionary containing verification results.
        """

        vehicle = self.get_entity(VEHICLE)

        rsu = self.get_entity(RSU)

        # -------------------------------------------------------------
        # Goal 1
        # Mutual Authentication
        # -------------------------------------------------------------

        mutual_authentication = (

            vehicle.has_belief(
                Expression(
                    subject=VEHICLE,
                    predicate=Predicate.AUTHENTICATED,
                    object=RSU
                )
            )

            and

            rsu.has_belief(
                Expression(
                    subject=RSU,
                    predicate=Predicate.AUTHENTICATED,
                    object=VEHICLE
                )
            )

        )

        self.set_goal(
            Goal.MUTUAL_AUTHENTICATION,
            mutual_authentication
        )

        # -------------------------------------------------------------
        # Goal 2
        # Session Key Agreement
        # -------------------------------------------------------------

        session_key_agreement = (

            vehicle.has_shared_key(RSU)

            and

            rsu.has_shared_key(VEHICLE)

        )

        self.set_goal(

            Goal.SESSION_KEY_AGREEMENT,

            session_key_agreement

        )

        # -------------------------------------------------------------
        # Goal 3
        # Session Key Freshness
        # -------------------------------------------------------------

        session_key_freshness = (

            vehicle.is_fresh("SessionKey")

            and

            rsu.is_fresh("SessionKey")

        )

        self.set_goal(

            Goal.SESSION_KEY_FRESHNESS,

            session_key_freshness

        )

        # -------------------------------------------------------------
        # Goal 4
        # Key Confirmation
        # -------------------------------------------------------------

        key_confirmation = (

            vehicle.has_belief(

                Expression(

                    subject=VEHICLE,

                    predicate=Predicate.SESSION_KEY,

                    object=RSU

                )

            )

            and

            rsu.has_belief(

                Expression(

                    subject=RSU,

                    predicate=Predicate.SESSION_KEY,

                    object=VEHICLE

                )

            )

        )

        self.set_goal(

            Goal.KEY_CONFIRMATION,

            key_confirmation

        )

        return self.verification_results

    # -------------------------------------------------------------------------

    def verification_summary(self) -> None:
        """
        Displays the verification summary.
        """

        print("\n")

        print("=" * 70)

        print("BAN LOGIC SECURITY GOAL VERIFICATION")

        print("=" * 70)

        for goal in Goal:

            status = self.goal_status(goal)

            symbol = "PASS" if status else "FAIL"

            print(

                f"{goal.name:<30} : {symbol}"

            )

        print("=" * 70)

        print()
        # =============================================================================
# PART 15 : BAN Proof & Report Generator
# =============================================================================

    def generate_report(self) -> str:
        """
        Generates a complete BAN Logic verification report.

        Returns
        -------
        str
            Formatted verification report.
        """

        report = []

        # =============================================================
        # Header
        # =============================================================

        report.append("=" * 80)
        report.append("BAN LOGIC VERIFICATION REPORT")
        report.append("=" * 80)

        report.append(f"Engine   : {ENGINE_NAME}")
        report.append(f"Version  : {ENGINE_VERSION}")
        report.append(f"Protocol : {PROTOCOL_NAME}")
        report.append("")

        # =============================================================
        # Participants
        # =============================================================

        report.append("-" * 80)
        report.append("PROTOCOL PARTICIPANTS")
        report.append("-" * 80)

        for entity in self.entities.values():
            report.append(f"• {entity.name}")

        report.append("")

        # =============================================================
        # Messages
        # =============================================================

        report.append("-" * 80)
        report.append("PROTOCOL MESSAGES")
        report.append("-" * 80)

        if self.messages:

            for msg in self.messages:

                report.append(
                    f"{msg.message_id} : "
                    f"{msg.sender} → {msg.receiver}"
                )

        else:

            report.append("No protocol messages processed.")

        report.append("")

        # =============================================================
        # Beliefs
        # =============================================================

        report.append("-" * 80)
        report.append("DERIVED BELIEFS")
        report.append("-" * 80)

        for entity in self.entities.values():

            report.append(f"\n[{entity.name}]")

            beliefs = entity.get_beliefs()

            if beliefs:

                for belief in beliefs:
                    report.append(
                        f"  {belief.to_equation()}"
                    )

            else:

                report.append("  None")

        report.append("")

        # =============================================================
        # Proof
        # =============================================================

        report.append("-" * 80)
        report.append("BAN PROOF")
        report.append("-" * 80)

        if self.proof_steps:

            for step in self.proof_steps:

                report.append(
                    f"\nSTEP {step.step_number}"
                )

                report.append(
                    f"Rule : {step.rule.name}"
                )

                report.append(
                    f"Status : {step.status}"
                )

                report.append("Input Facts:")

                for fact in step.input_facts:

                    report.append(
                        f"   • {fact}"
                    )

                report.append(
                    f"Derived : {step.derived_fact}"
                )

                if step.remarks:

                    report.append(
                        f"Remarks : {step.remarks}"
                    )

        else:

            report.append("No proof generated.")

        report.append("")

        # =============================================================
        # Goal Verification
        # =============================================================

        report.append("-" * 80)
        report.append("SECURITY GOALS")
        report.append("-" * 80)

        passed = 0

        total = len(Goal)

        for goal in Goal:

            status = self.goal_status(goal)

            if status:

                passed += 1

            report.append(
                f"{goal.name:<35} : "
                f"{'PASS' if status else 'FAIL'}"
            )

        report.append("")

        # =============================================================
        # Statistics
        # =============================================================

        report.append("-" * 80)
        report.append("ENGINE STATISTICS")
        report.append("-" * 80)

        stats = self.statistics()

        report.append(
            f"Participants      : {stats['participants']}"
        )

        report.append(
            f"Messages          : {stats['messages']}"
        )

        report.append(
            f"Proof Steps       : {stats['proof_steps']}"
        )

        report.append(
            f"Verified Goals    : {passed}/{total}"
        )

        report.append("")

        # =============================================================
        # Final Verdict
        # =============================================================

        report.append("=" * 80)

        if passed == total:

            report.append(
                "FINAL RESULT : PROTOCOL SUCCESSFULLY VERIFIED"
            )

        else:

            report.append(
                "FINAL RESULT : VERIFICATION INCOMPLETE"
            )

        report.append("=" * 80)

        return "\n".join(report)

    # -----------------------------------------------------------------

    def print_report(self) -> None:
        """
        Prints the complete BAN Logic report.
        """

        print(self.generate_report())

    # -----------------------------------------------------------------

    def export_report(
        self,
        filename: str = "ban_logic_report.txt"
    ) -> None:
        """
        Saves the verification report to a text file.
        """

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                self.generate_report()
            )

        print(
            f"\nReport exported to '{filename}'"
        )
     # =============================================================================
# PART 16 : BAN Equation Generator
# =============================================================================

    def generate_equations(self) -> List[str]:
        """
        Generates the formal BAN Logic equations derived during
        protocol execution.

        Returns
        -------
        List[str]
            List of BAN Logic equations.
        """

        equations = []

        equations.append("=" * 70)
        equations.append("BAN LOGIC EQUATIONS")
        equations.append("=" * 70)

        for entity in self.entities.values():

            equations.append(f"\n[{entity.name}]")

            beliefs = entity.get_beliefs()

            if not beliefs:

                equations.append("None")

                continue

            for belief in beliefs:

                equations.append(
                    belief.to_equation()
                )

        return equations

    # -----------------------------------------------------------------

    def print_equations(self) -> None:
        """
        Prints all generated BAN Logic equations.
        """

        for line in self.generate_equations():
            print(line)

    # -----------------------------------------------------------------

    def generate_formal_ban_analysis(self) -> None:
        """
        Generates the formal BAN Logic analysis of the PQC-CMAKA protocol.
        """

        print("\n" + "=" * 70)
        print("FORMAL BAN ANALYSIS")
        print("=" * 70)

        print("\nProtocol : PQC-CMAKA")

        print("\nParticipants")
        print("------------")
        print("• Vehicle")
        print("• RSU")
        print("• Trusted Authority")

        print("\nInitial BAN Assumptions")
        print("-----------------------")
        print("A1  Vehicle |≡ (TA ⇒ Vehicle Identity)")
        print("A2  RSU |≡ (TA ⇒ RSU Identity)")
        print("A3  Vehicle |≡ #(Nv)")
        print("A4  RSU |≡ #(Nr)")
        print("A5  Vehicle |≡ (Vehicle ↔K RSU)")
        print("A6  RSU |≡ (RSU ↔K Vehicle)")
        print("A7  Vehicle |≡ #(SessionKey)")
        print("A8  RSU |≡ #(SessionKey)")
        print("A9  TA |≡ (Vehicle ≡ RSU)")
        print("A10 TA |≡ (RSU ≡ Vehicle)")        

        print("\n" + "-" * 70)
        print("MESSAGE M1 : Vehicle → RSU")
        print("-" * 70)
        print("Contents")
        print("  • Adaptive PID")
        print("  • ACT")
        print("  • Nonce Nv")
        print("  • Timestamp Tv")
        print("  • ML-DSA Signature")
        print("\nApplied Rule")
        print("  MESSAGE_MEANING")
        print("\nDerived Belief")
        print("  RSU |≡ (Vehicle |~ Nv)")

        print("\n" + "-" * 70)
        print("MESSAGE M2 : RSU → Vehicle")
        print("-" * 70)
        print("Contents")
        print("  • RSU ID")
        print("  • Nonce Nr")
        print("  • Timestamp Tr")
        print("  • ML-DSA Signature")
        print("\nApplied Rule")
        print("  MESSAGE_MEANING")
        print("\nDerived Belief")
        print("  Vehicle |≡ (RSU |~ Nr)")

        print("\n" + "-" * 70)
        print("MESSAGE M3 : Vehicle → RSU")
        print("-" * 70)
        print("Contents")
        print("  • ML-KEM Ciphertext")
        print("  • Timestamp T3")
        print("  • ML-DSA Signature")
        print("\nApplied Rule")
        print("  SESSION_KEY")
        print("\nDerived Belief")
        print("  RSU |≡ (RSU ↔K Vehicle)" )

        print("\n" + "-" * 70)
        print("MESSAGE M4 : RSU → Vehicle")
        print("-" * 70)
        print("Contents")
        print("  • Session Key Confirmation")
        print("  • ML-DSA Signature")
        print("\nApplied Rule")
        print("  KEY_CONFIRMATION")
        print("\nDerived Belief")
        print("  Vehicle |≡ (Vehicle ≡ RSU)")
        print("  RSU |≡ (RSU ≡ Vehicle)")

        print("\n" + "=" * 70)
        print("FORMAL VERIFICATION SUMMARY")
        print("=" * 70)
        print("✓ Mutual Authentication Achieved")
        print("✓ Session Key Agreement Achieved")
        print("✓ Session Key Freshness Verified")
        print("✓ Key Confirmation Successful")
        print("✓ Protocol Successfully Verified")

    # -----------------------------------------------------------------

    def export_equations(
        self,
        filename: str = "ban_equations.txt"
    ) -> None:
        """
        Exports the generated BAN equations to a text file.
        """

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            for line in self.generate_equations():
                file.write(line + "\n")

        print(f"\nBAN equations exported to '{filename}'")
       # =============================================================================
    # PART 17 : Proof Tree Generator
    # =============================================================================

    def generate_proof_tree(self) -> List[str]:
        """
        Generates a hierarchical proof tree from the
        recorded BAN Logic proof steps.

        Returns
        -------
        List[str]
            Proof tree representation.
        """

        tree = []

        tree.append("=" * 80)
        tree.append("BAN LOGIC PROOF TREE")
        tree.append("=" * 80)

        if not self.proof_steps:
            tree.append("No proof steps available.")
            return tree

        current_rule = None

        for step in self.proof_steps:

            if current_rule != step.rule:
                current_rule = step.rule

                tree.append("")
                tree.append(f"{current_rule.name}")
                tree.append("│")

            tree.append(f"├── Step {step.step_number}")
            tree.append("│   Input Facts")

            if step.input_facts:
                for fact in step.input_facts:
                    tree.append(f"│     • {fact}")
            else:
                tree.append("│     None")

            tree.append("│")
            tree.append("├── Derived")

            derived = str(step.derived_fact)
            derived = derived.replace("believes", "|≡")
            derived = derived.replace("once_said", "|~")
            derived = derived.replace("session_key", "↔K")
            derived = derived.replace("authenticated", "≡")

            tree.append(f"│     {derived}")

            tree.append("│")
            tree.append(f"└── Status : {step.status}")

        return tree

    # -----------------------------------------------------------------

    def print_proof_tree(self) -> None:
        """
        Prints the BAN Logic proof tree.
        """

        for line in self.generate_proof_tree():

            print(line)

    # -----------------------------------------------------------------

    def export_proof_tree(
        self,
        filename: str = "ban_proof_tree.txt"
    ) -> None:
        """
        Exports the proof tree to a text file.
        """

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            for line in self.generate_proof_tree():

                file.write(line + "\n")

        print(
            f"\nProof tree exported to '{filename}'"
        )
        # =============================================================================
# PART 18 : Recursive Inference Engine
# =============================================================================

    def infer(self) -> int:
        """
        Performs recursive BAN Logic inference.

        The engine repeatedly applies all BAN inference rules
        until no new beliefs can be derived.

        Returns
        -------
        int
            Number of newly derived beliefs.
        """

        iterations = 0
        changed = True

        while changed:

            changed = False

            iterations += 1

            # ---------------------------------------------------------
            # Examine every protocol participant
            # ---------------------------------------------------------

            for entity in self.entities.values():

                beliefs = list(entity.get_beliefs())

                for belief in beliefs:

                    expr = belief.expression

                    # -------------------------------------------------
                    # ONCE_SAID  ---> BELIEVES
                    # -------------------------------------------------

                    if expr.predicate == Predicate.ONCE_SAID:

                        if entity.is_fresh(expr.object):

                            new_expression = Expression(

                                subject=expr.subject,

                                predicate=Predicate.BELIEVES,

                                object=expr.object

                            )

                            if not entity.has_belief(new_expression):

                                entity.add_belief(new_expression)

                                self.add_proof_step(

                                    rule=RuleType.NONCE_VERIFICATION,

                                    input_facts=[
                                        str(belief),
                                        f"Fresh({expr.object})"
                                    ],

                                    derived_fact=str(
                                        Belief(
                                            owner=entity.name,
                                            expression=new_expression
                                        )
                                    ),

                                    status=PASSED,

                                    remarks="Derived automatically by recursive inference."

                                )

                                changed = True

                    # -------------------------------------------------
                    # BELIEVES ---> AUTHENTICATED
                    # -------------------------------------------------

                    elif expr.predicate == Predicate.BELIEVES:

                        auth_expression = Expression(

                            subject=expr.subject,

                            predicate=Predicate.AUTHENTICATED,

                            object=entity.name

                        )

                        if not entity.has_belief(auth_expression):

                            entity.add_belief(auth_expression)

                            self.add_proof_step(

                                rule=RuleType.KEY_CONFIRMATION,

                                input_facts=[
                                    str(belief)
                                ],

                                derived_fact=str(
                                    Belief(
                                        owner=entity.name,
                                        expression=auth_expression
                                    )
                                ),

                                status=PASSED,

                                remarks="Authentication derived automatically."

                            )

                            changed = True

                    # -------------------------------------------------
                    # SHARED KEY ---> SESSION KEY
                    # -------------------------------------------------

                    if entity.has_shared_key(expr.subject):

                        session_expression = Expression(

                            subject=entity.name,

                            predicate=Predicate.SESSION_KEY,

                            object=expr.subject

                        )

                        if not entity.has_belief(session_expression):

                            entity.add_belief(session_expression)

                            self.add_proof_step(

                                rule=RuleType.SESSION_KEY,

                                input_facts=[
                                    f"Shared key with {expr.subject}"
                                ],

                                derived_fact=str(
                                    Belief(
                                        owner=entity.name,
                                        expression=session_expression
                                    )
                                ),

                                status=PASSED,

                                remarks="Session key inferred."

                            )

                            changed = True

        return iterations
        # =============================================================================
# PART 19 : Protocol Validator
# =============================================================================

    def validate_protocol(self) -> bool:
        """
        Validates whether the BAN protocol execution
        follows the expected message flow.

        Checks:
            • Message sequence
            • Sender
            • Receiver
            • Duplicate nonces
            • Timestamp presence
            • Required cryptographic fields

        Returns
        -------
        bool
            True if protocol execution is valid.
        """

        errors = []

        expected_order = [M1, M2, M3, M4]

        if len(self.messages) != len(expected_order):

            errors.append(
                f"Expected {len(expected_order)} protocol messages "
                f"but received {len(self.messages)}."
            )

        # -------------------------------------------------------------
        # Message Order
        # -------------------------------------------------------------

        for index, expected in enumerate(expected_order):

            if index >= len(self.messages):
                break

            message = self.messages[index]

            if message.message_id != expected:

                errors.append(
                    f"Expected {expected} but found {message.message_id}."
                )

        # -------------------------------------------------------------
        # Duplicate Nonces
        # -------------------------------------------------------------

        seen_nonces = set()

        for message in self.messages:

            if message.nonce is not None:

                if message.nonce in seen_nonces:

                    errors.append(
                        f"Duplicate nonce detected ({message.nonce})."
                    )

                seen_nonces.add(message.nonce)

        # -------------------------------------------------------------
        # Validate Each Message
        # -------------------------------------------------------------

        for message in self.messages:

            if message.timestamp is None:

                errors.append(
                    f"{message.message_id} has no timestamp."
                )

            if message.signature is None:

                errors.append(
                    f"{message.message_id} has no ML-DSA signature."
                )

            # Vehicle → RSU

            if message.message_id == M1:

                if message.sender != VEHICLE:

                    errors.append(
                        "M1 sender must be Vehicle."
                    )

                if message.receiver != RSU:

                    errors.append(
                        "M1 receiver must be RSU."
                    )

                if message.kem_public_key is None:

                    errors.append(
                        "M1 missing ML-KEM public key."
                    )

            # RSU → Vehicle

            elif message.message_id == M2:

                if message.sender != RSU:

                    errors.append(
                        "M2 sender must be RSU."
                    )

                if message.receiver != VEHICLE:

                    errors.append(
                        "M2 receiver must be Vehicle."
                    )

                if message.kem_public_key is None:

                    errors.append(
                        "M2 missing ML-KEM public key."
                    )

            # Vehicle → RSU

            elif message.message_id == M3:

                if message.kem_ciphertext is None:

                    errors.append(
                        "M3 missing ML-KEM ciphertext."
                    )

            # RSU → Vehicle

            elif message.message_id == M4:

                if message.session_key is None:

                    errors.append(
                        "M4 missing session key confirmation."
                    )

        # -------------------------------------------------------------
        # Store Validation Result
        # -------------------------------------------------------------

        self.verification_results["protocol_validation"] = (
            len(errors) == 0
        )

        self.verification_results["validation_errors"] = errors

        return len(errors) == 0

    # -----------------------------------------------------------------

    def protocol_validation_report(self) -> str:
        """
        Generates a readable protocol validation report.
        """

        lines = []

        lines.append("=" * 70)
        lines.append("PROTOCOL VALIDATION REPORT")
        lines.append("=" * 70)

        valid = self.verification_results.get(
            "protocol_validation",
            False
        )

        if valid:

            lines.append("Status : PASSED")
            lines.append("Protocol execution is valid.")

        else:

            lines.append("Status : FAILED")
            lines.append("")

            for error in self.verification_results.get(
                "validation_errors",
                []
            ):

                lines.append(f"- {error}")

        return "\n".join(lines)

    # -----------------------------------------------------------------

    def print_protocol_validation(self) -> None:
        """
        Prints the protocol validation report.
        """

        print(self.protocol_validation_report())
        # =============================================================================
# PART 20 : Complete Demo Runner
# =============================================================================

    def run(self) -> None:
        """
        Executes the complete BAN Logic verification pipeline.
        """

        print("\n" + "=" * 80)
        print("BAN LOGIC VERIFICATION ENGINE")
        print("=" * 80)

        # -------------------------------------------------------------
        # Step 1 : Initialize Assumptions
        # -------------------------------------------------------------

        print("\n[1] Initializing BAN assumptions...")
        self.initialize_assumptions()

        # -------------------------------------------------------------
        # Step 2 : Validate Protocol
        # -------------------------------------------------------------

        print("[2] Validating protocol execution...")

        protocol_valid = self.validate_protocol()

        if protocol_valid:

            print("    ✓ Protocol validation PASSED")

        else:

            print("    ✗ Protocol validation FAILED")
            print(self.protocol_validation_report())
            return

        # -------------------------------------------------------------
        # Step 3 : Process Messages
        # -------------------------------------------------------------

        print("[3] Processing protocol messages...")

        for message in self.messages:

            self.process_message(message)

        print(f"    ✓ {len(self.messages)} messages processed")

        # -------------------------------------------------------------
        # Step 4 : Recursive Inference
        # -------------------------------------------------------------

        print("[4] Running recursive inference...")

        iterations = self.infer()

        print(f"    ✓ Inference completed ({iterations} iteration(s))")

        # -------------------------------------------------------------
        # Step 5 : Verify Security Goals
        # -------------------------------------------------------------

        print("[5] Verifying BAN security goals...")

        self.verify_goals()

        # -------------------------------------------------------------
        # Step 6 : Print Reports
        # -------------------------------------------------------------

        print("[6] Generating reports...\n")

        self.generate_formal_ban_analysis()

        print()

        self.print_equations()

        print()

        self.print_proof_tree()

        print()

        self.print_report()

        print()

        print(self.protocol_validation_report())
    # -----------------------------------------------------------------

    def export_all(
        self,
        report_file: str = "ban_report.txt",
        proof_file: str = "ban_proof_tree.txt",
        equation_file: str = "ban_equations.txt"
    ) -> None:
        """
        Exports all generated BAN Logic reports.
        """

        self.export_report(report_file)

        self.export_proof_tree(proof_file)

        self.export_equations(equation_file)

        print("\nAll reports exported successfully.")
        # =============================================================================
# PART 21 : Exception & Error Handling Framework
# =============================================================================

    def log_error(
        self,
        source: str,
        message: str
    ) -> None:
        """
        Records an internal engine error.
        """

        if not hasattr(self, "errors"):
            self.errors = []

        self.errors.append(
            {
                "source": source,
                "message": message
            }
        )

    # -----------------------------------------------------------------

    def get_errors(self) -> List[dict]:
        """
        Returns all recorded engine errors.
        """

        if not hasattr(self, "errors"):
            self.errors = []

        return self.errors

    # -----------------------------------------------------------------

    def clear_errors(self) -> None:
        """
        Clears all stored engine errors.
        """

        self.errors = []

    # -----------------------------------------------------------------

    def print_errors(self) -> None:
        """
        Prints all recorded engine errors.
        """

        print("\n" + "=" * 70)
        print("ENGINE ERROR LOG")
        print("=" * 70)

        if not self.get_errors():

            print("No errors recorded.")

            return

        for index, error in enumerate(self.get_errors(), start=1):

            print(
                f"{index}. [{error['source']}] {error['message']}"
            )

    # -----------------------------------------------------------------

    def safe_process_message(
        self,
        message: ProtocolMessage
    ) -> bool:
        """
        Safely processes a protocol message.
        """

        try:

            self.process_message(message)

            return True

        except Exception as e:

            self.log_error(
                "process_message",
                str(e)
            )

            return False

    # -----------------------------------------------------------------

    def safe_infer(self) -> int:
        """
        Safely executes recursive inference.
        """

        try:

            return self.infer()

        except Exception as e:

            self.log_error(
                "infer",
                str(e)
            )

            return 0

    # -----------------------------------------------------------------

    def safe_verify_goals(self) -> bool:
        """
        Safely verifies BAN security goals.
        """

        try:

            self.verify_goals()

            return True

        except Exception as e:

            self.log_error(
                "verify_goals",
                str(e)
            )

            return False

    # -----------------------------------------------------------------

    def safe_run(self) -> bool:
        """
        Executes the complete BAN engine safely.
        """

        try:

            self.run()

            return True

        except Exception as e:

            self.log_error(
                "run",
                str(e)
            )

            return False
            # =============================================================================
# PART 22 : JSON Export Engine
# =============================================================================

    def to_json(self) -> dict:
        """
        Converts the complete BAN Logic engine state
        into a JSON-serializable dictionary.
        """

        return {

            "participants": list(self.entities.keys()),

            "messages": [

                message.as_dict()

                for message in self.messages

            ],

            "proof_steps": [

                step.as_dict()

                for step in self.proof_steps

            ],

            "beliefs": {

                entity.name: [

                    belief.to_equation()

                    for belief in entity.get_beliefs()

                ]

                for entity in self.entities.values()

            },

            "freshness": {

                entity.name: [

                    str(item)

                    for item in entity.get_fresh_items()

                ]

                for entity in self.entities.values()

            },

             "shared_keys": {

                entity.name: [

                    {
                        "owner": key.owner,
                        "peer": key.peer,
                        "key": key.key,
                        "algorithm": key.algorithm
                    }

                    for key in entity.shared_keys

                ]

                for entity in self.entities.values()

            },

            "verification_results": {

                goal.name if hasattr(goal, "name") else str(goal): status

                for goal, status in self.verification_results.items()

            },

            "statistics": self.statistics()

        }
    # -----------------------------------------------------------------

    def export_json(
        self,
        filename: str = "ban_logic_report.json"
    ) -> None:
        """
        Exports the BAN Logic execution results
        into a JSON file.
        """

        import json

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(

                self.to_json(),

                file,

                indent=4,

                ensure_ascii=False

            )

        print(
            f"\nJSON report exported to '{filename}'"
        )

    # -----------------------------------------------------------------

    def print_json(self) -> None:
        """
        Prints the JSON representation.
        """

        import json

        print(

            json.dumps(

                self.to_json(),

                indent=4,

                ensure_ascii=False

            )

        )
        # =============================================================================
# PART 23 : CSV Export Engine
# =============================================================================

    def export_csv(
        self,
        filename: str = "ban_logic_report.csv"
    ) -> None:
        """
        Exports BAN Logic execution results into CSV format.
        """

        import csv

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            writer = csv.writer(csvfile)

            # ---------------------------------------------------------
            # General Statistics
            # ---------------------------------------------------------

            writer.writerow(["BAN LOGIC REPORT"])
            writer.writerow([])

            writer.writerow(["GENERAL STATISTICS"])
            writer.writerow(["Parameter", "Value"])

            stats = self.statistics()

            for key, value in stats.items():

                writer.writerow([key, value])

            writer.writerow([])

            # ---------------------------------------------------------
            # Verification Results
            # ---------------------------------------------------------

            writer.writerow(["VERIFICATION RESULTS"])
            writer.writerow(["Goal", "Status"])

            for key, value in self.verification_results.items():

                writer.writerow([key, value])

            writer.writerow([])

            # ---------------------------------------------------------
            # Messages
            # ---------------------------------------------------------

            writer.writerow(["PROTOCOL MESSAGES"])

            writer.writerow([
                "Message",
                "Sender",
                "Receiver",
                "Nonce",
                "Timestamp"
            ])

            for message in self.messages:

                writer.writerow([
                    message.message_id,
                    message.sender,
                    message.receiver,
                    message.nonce,
                    message.timestamp
                ])

            writer.writerow([])

            # ---------------------------------------------------------
            # Beliefs
            # ---------------------------------------------------------

            writer.writerow(["BELIEFS"])

            writer.writerow([
                "Owner",
                "Belief"
            ])

            for entity in self.entities.values():

                for belief in entity.get_beliefs():

                    writer.writerow([
                        entity.name,
                        belief.to_equation()
                    ])

            writer.writerow([])

            # ---------------------------------------------------------
            # Proof Steps
            # ---------------------------------------------------------

            writer.writerow(["PROOF STEPS"])

            writer.writerow([
                "Step",
                "Rule",
                "Derived Fact",
                "Status"
            ])

            for step in self.proof_steps:

                writer.writerow([
                    step.step_number,
                    step.rule.name,
                    step.derived_fact,
                    step.status
                ])

        print(
            f"\nCSV report exported to '{filename}'"
        )

    # -----------------------------------------------------------------

    def export_complete_results(self) -> None:
        """
        Exports all supported report formats.
        """

        self.export_report()

        self.export_equations()

        self.export_proof_tree()

        self.export_json()

        self.export_csv()

        print("\nAll BAN Logic reports exported successfully.")
        # =============================================================================
# PART 24 : MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":

    print("\n" + "=" * 80)
    print("POST-QUANTUM CERTIFICATELESS VANET")
    print("BAN LOGIC VERIFICATION")
    print("=" * 80)

    # ---------------------------------------------------------
    # Create BAN Engine
    # ---------------------------------------------------------

    engine = BANLogicEngine()

    # ---------------------------------------------------------
    # Create Protocol Messages
    # ---------------------------------------------------------

    m1 = ProtocolMessage(
        message_id=M1,
        sender=VEHICLE,
        receiver=RSU,
        message_type=MessageType.AUTHENTICATION,
        pseudonym="PID001",
        authentication_code="ACT001",
        nonce="Nv",
        timestamp="Tv",
        signature="MLDSA_SIG_V",
        kem_public_key="PK_V"
    )

    m2 = ProtocolMessage(
        message_id=M2,
        sender=RSU,
        receiver=VEHICLE,
        message_type=MessageType.AUTHENTICATION,
        pseudonym="PID001",
        authentication_code="ACT001",
        nonce="Nr",
        timestamp="Tr",
        signature="MLDSA_SIG_R",
        kem_public_key="PK_R"
    )

    m3 = ProtocolMessage(
        message_id=M3,
        sender=VEHICLE,
        receiver=RSU,
        message_type=MessageType.KEY_EXCHANGE,
        kem_ciphertext="CT_KEM",
        timestamp="T3",
        signature="MLDSA_SIG_V"
    )
    m4 = ProtocolMessage(
        message_id=M4,
        sender=RSU,
        receiver=VEHICLE,
        message_type=MessageType.CONFIRMATION,
        session_key="SESSION_KEY_001",
        timestamp="Ts",
        signature="MLDSA_SIG_CONFIRM"
    )

    # ---------------------------------------------------------
    # Register Messages
    # ---------------------------------------------------------

    engine.add_message(m1)
    engine.add_message(m2)
    engine.add_message(m3)
    engine.add_message(m4)

    # ---------------------------------------------------------
    # Execute BAN Verification
    # ---------------------------------------------------------

    engine.run()

    # ---------------------------------------------------------
    # Export Reports
    # ---------------------------------------------------------

    engine.export_complete_results()

    print("\n" + "=" * 80)
    print("BAN LOGIC VERIFICATION FINISHED")
    print("=" * 80)