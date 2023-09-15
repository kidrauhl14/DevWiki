// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;  

import '@openzeppelin/contracts/token/ERC721/ERC721.sol';
import '@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol';

contract ERC721sample is ERC721URIStorage{
    constructor() ERC721("devwiki", "DVW"){} 

    uint public _id;

    function mintNFT(address _a, string memory _b) public {
        _mint(_a, _id);
        _setTokenURI(_id,_b);
        _id++;
    }
    receive() external payable{} 
}