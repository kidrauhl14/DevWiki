/** @type import('hardhat/config').HardhatUserConfig */
const PVK = "8bfe050973a1d5330813f1e32c8531ca25913b1318f891e1b2117c6c058f356c";
module.exports = {
  solidity: "0.8.7",
  networks: {
    goerli: {
      url: `https://eth-goerli.g.alchemy.com/v2/vrRKGTYR7Wo9KLlV5qJrwLEy96Ya4bpH`,
      accounts: [PVK],
    },
  },
  etherscan: {
    apiKey: "D3PF3JGZ7SQ4V1TIDTKW735GBY1UXVJ6PV",
  },
};
