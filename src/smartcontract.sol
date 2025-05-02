// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract KeySharesManager {
    // Struct to store key shares data
    struct KeySharesData {
        uint256 chunks;
        uint256 totalLength;
        bool exists;
        // The actual shares data is stored in a separate mapping for efficient updates
    }
    
    // Mapping from username hash to their key shares metadata
    mapping(bytes32 => KeySharesData) private userKeyData;
    
    // Mapping from username hash + chunk index to shares array 
    // (username hash -> chunk index -> formatted share data)
    mapping(bytes32 => mapping(uint256 => string)) private shareChunks;
    
    // Access control - only the server with this address can modify data
    address private serverAddress;
    
    // Events
    event KeySharesStored(bytes32 indexed usernameHash);
    event KeySharesRetrieved(bytes32 indexed usernameHash);
    
    constructor() {
        serverAddress = msg.sender;
    }
    
    // Modifier to restrict access to the server
    modifier onlyServer() {
        require(msg.sender == serverAddress, "Only the server can call this function");
        _;
    }
    
    function storeKeyShares(
        string memory username,
        uint256 chunks, 
        uint256 totalLength,
        string[] memory serializedShares
    ) external onlyServer returns (bool) {
        bytes32 usernameHash = keccak256(abi.encodePacked(username));
        
        // Store metadata
        userKeyData[usernameHash] = KeySharesData({
            chunks: chunks,
            totalLength: totalLength,
            exists: true
        });
        
        // Store each chunk of shares
        for (uint256 i = 0; i < serializedShares.length; i++) {
            shareChunks[usernameHash][i] = serializedShares[i];
        }
        
        emit KeySharesStored(usernameHash);
        return true;
    }
    
    function retrieveKeyShares(string memory username) 
        external 
        view 
        returns (
            uint256 chunks,
            uint256 totalLength,
            string[] memory serializedShares
        ) 
    {
        bytes32 usernameHash = keccak256(abi.encodePacked(username));
        
        // Check if user exists
        require(userKeyData[usernameHash].exists, "No key shares found for this user");
        
        KeySharesData memory data = userKeyData[usernameHash];
        string[] memory shares = new string[](data.chunks);
        
        // Retrieve each chunk
        for (uint256 i = 0; i < data.chunks; i++) {
            shares[i] = shareChunks[usernameHash][i];
        }
        
        return (data.chunks, data.totalLength, shares);
    }
    
    function userExists(string memory username) external view returns (bool) {
        bytes32 usernameHash = keccak256(abi.encodePacked(username));
        return userKeyData[usernameHash].exists;
    }
    
    function deleteUser(string memory username) external onlyServer {
        bytes32 usernameHash = keccak256(abi.encodePacked(username));
        
        require(userKeyData[usernameHash].exists, "User does not exist");
        
        // Delete metadata
        uint256 chunks = userKeyData[usernameHash].chunks;
        delete userKeyData[usernameHash];
        
        // Delete each chunk
        for (uint256 i = 0; i < chunks; i++) {
            delete shareChunks[usernameHash][i];
        }
    }
}