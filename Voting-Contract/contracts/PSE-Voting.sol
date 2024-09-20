// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Bn128.sol";
// import "./hardhat/console.sol";

contract PseVoting {
    address public owner;
    Bn128.G1Point[] ck;
    
    uint candidateLimit;
    uint256[] vk;

    struct Candidate {
        uint candidateNumber;
        address candidateAddress;
        string name;
        Vote[] voteCount;
        Vote aggregateVote;
    }

    struct Vote {
        Bn128.G1Point g_r;
        Bn128.G1Point g_mh_r;
    }

    struct VotingRound {
        bool registrationOpen;
        bool votingOpen;
        uint currentVotingRound;
        mapping(address => Candidate) candidates;
        mapping(uint => bool) serialNumberUsed;
        address[] candidateAddresses;
        uint totalCandidate;
        uint[] voterAddresses;
        uint[] proofs;
        uint root;
    }

    uint public votingRoundCounter;
    mapping(uint => VotingRound) public votingRounds;

    event VotingRoundCreated(uint votingRoundNumber);
    event CandidateRegistered(uint indexed votingRoundNumber, address indexed candidateAddress, string name);
    event VoteSubmitted(uint indexed votingRoundNumber, uint serialNumber, Vote[] votes);

    constructor(uint[] memory _ck, uint[] memory _vk, uint _candidateLimit) {
        owner = msg.sender;
        votingRoundCounter = 0;
        vk = _vk;
        candidateLimit = _candidateLimit;
        Bn128.G1Point memory g = Bn128.G1Point(_ck[0], _ck[1]);
        Bn128.G1Point memory h = Bn128.G1Point(_ck[2], _ck[3]);
        ck.push(g);
        ck.push(h);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function proofVerify(uint[] memory _proof, uint[] memory _inputs) internal view returns (bool) {
        require(_proof.length == 10, "proof length must be 10");
        require(_inputs.length == 4 + candidateLimit, "Invalid inputs length");
        return true;
    }

    function aggregateVotes(Vote[] memory _votes) internal view returns (Vote memory) {
        Vote memory aggregateVote;
        aggregateVote.g_r = _votes[0].g_r;
        aggregateVote.g_mh_r = _votes[0].g_mh_r;

        for (uint i = 1; i < _votes.length; i++) {
            aggregateVote.g_r = Bn128.add(aggregateVote.g_r, _votes[i].g_r);
            aggregateVote.g_mh_r = Bn128.add(aggregateVote.g_mh_r, _votes[i].g_mh_r);
        }
        return aggregateVote;
    }

    function createVotingRound() external onlyOwner {
        votingRoundCounter++;
        VotingRound storage round = votingRounds[votingRoundCounter];
        round.registrationOpen = false;
        round.votingOpen = false;
        round.currentVotingRound = votingRoundCounter;
        round.totalCandidate = 0;
        round.root = 0;
        emit VotingRoundCreated(votingRoundCounter);
    }

    function openRegistration(uint _votingRoundNumber) external onlyOwner {
        VotingRound storage round = votingRounds[_votingRoundNumber];
        require(!round.registrationOpen, "Registration is already open");
        round.registrationOpen = true;
    }

    function openVoting(uint _votingRoundNumber, uint _root) external onlyOwner {
        VotingRound storage round = votingRounds[_votingRoundNumber];
        require(round.registrationOpen, "Registration is not open");
        require(!round.votingOpen, "Voting is already open");
        round.root = _root;
        round.registrationOpen = false;
        round.votingOpen = true;
    }

    function CloseVoting(uint votingRoundNumber) external onlyOwner {
        VotingRound storage round = votingRounds[votingRoundNumber];
        require(round.votingOpen, "Voting is not open");
        round.votingOpen = false;
        for (uint i = 0; i < round.candidateAddresses.length; i++) {
            round.candidates[round.candidateAddresses[i]].aggregateVote = aggregateVotes(round.candidates[round.candidateAddresses[i]].voteCount);
        }
    }

    function registerCandidate(uint _votingRoundNumber, string memory _name) external {
        VotingRound storage round = votingRounds[_votingRoundNumber];
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(round.registrationOpen, "Registration is not open");
        require(round.candidates[msg.sender].candidateNumber == 0, "Candidate already registered");
        require(round.totalCandidate < candidateLimit, "Candidate limit reached");

        
        uint candidateNumber = ++round.totalCandidate;

        Candidate storage candidate = round.candidates[msg.sender];
        candidate.candidateNumber = candidateNumber;
        candidate.candidateAddress = msg.sender;
        candidate.name = _name;

        round.candidateAddresses.push(msg.sender);
        emit CandidateRegistered(_votingRoundNumber, msg.sender, _name);
    }

    function registerVoter(uint _votingRoundNumber, uint _addr) external {
        VotingRound storage round = votingRounds[_votingRoundNumber];
        require(round.registrationOpen, "Registration is not open");

        for (uint i = 0; i < round.voterAddresses.length; i++) {
            require(round.voterAddresses[i] != _addr, "Voter already registered");
        }

        round.voterAddresses.push(_addr);
    }

    function submitVote(uint _votingRoundNumber, uint sn, Vote[] memory voteList, uint[] memory proof, uint[] memory inputs) external {
        VotingRound storage round = votingRounds[_votingRoundNumber];
        require(proofVerify(proof, inputs), "Invalid proof");
        require(!round.serialNumberUsed[sn], "Serial number already used");
        round.serialNumberUsed[sn] = true;

        for (uint i = 0; i < voteList.length; i++) {
            address candidateAddress = round.candidateAddresses[i];
            round.candidates[candidateAddress].voteCount.push(voteList[i]);
        }

        emit VoteSubmitted(_votingRoundNumber, sn, voteList);
    }

    function getCk() external view returns (uint[] memory) {
        uint[] memory ckArray = new uint[](4);
        ckArray[0] = ck[0].X;
        ckArray[1] = ck[0].Y;
        ckArray[2] = ck[1].X;
        ckArray[3] = ck[1].Y;
        return ckArray;
    }

    function getCandidates(uint _votingRoundCounter) external view returns (address[] memory) {
        return votingRounds[_votingRoundCounter].candidateAddresses;
    }

    function getVoterAddresses(uint _votingRoundCounter) external view returns (uint[] memory) {
        return votingRounds[_votingRoundCounter].voterAddresses;
    }

    function getVotingRoundInfo(uint _votingRoundCounter) external view returns (uint, uint, uint, uint, uint[] memory) {
        VotingRound storage round = votingRounds[_votingRoundCounter];
        return (round.currentVotingRound, round.totalCandidate, round.root, round.voterAddresses.length, round.voterAddresses);
    }

    function getAggregateVote(uint _votingRoundCounter, uint candidatePos) external view returns (uint, uint) {
        VotingRound storage round = votingRounds[_votingRoundCounter];
        return (round.candidates[round.candidateAddresses[candidatePos]].aggregateVote.g_r.X, round.candidates[round.candidateAddresses[candidatePos]].aggregateVote.g_r.Y);
    }
}