contract Events {
    event TokenPurchase(
        address indexed buyer,
        uint256 indexed trx_sold,
        uint256 indexed tokens_bought
    );
    event TrxPurchase(
        address indexed buyer,
        uint256 indexed tokens_sold,
        uint256 indexed trx_bought
    );
    event AddLiquidity(
        address indexed provider,
        uint256 indexed trx_amount,
        uint256 indexed token_amount
    );
    event RemoveLiquidity(
        address indexed provider,
        uint256 indexed trx_amount,
        uint256 indexed token_amount
    );
    event Snapshot(
        address indexed operator,
        uint256 indexed trx_balance,
        uint256 indexed token_balance
    );

    // IJustswapFactory
    event NewExchange(address indexed token, address indexed exchange);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    event EthPurchase(
        address indexed buyer,
        uint256 indexed tokens_sold,
        uint256 indexed eth_bought
    );

    // Uniswap V2
    event PairCreated(
        address indexed token0,
        address indexed token1,
        address pair,
        uint256
    );
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(
        address indexed sender,
        uint256 amount0,
        uint256 amount1,
        address indexed to
    );
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);
}
