// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 321267386186892361787893782439982736488276932020344871952240340341690294362;
    uint256 constant alphay  = 3645973699894535979859721866722947026547402862069842172567138159163072620303;
    uint256 constant betax1  = 16858568151901782659163799644368872129620357527545472932698298418682438619112;
    uint256 constant betax2  = 16109439579741414744105248650251506385961388743435318677868822236790139468452;
    uint256 constant betay1  = 10134953891981349726256741849925027871670832843455532672396139050944218820473;
    uint256 constant betay2  = 14284207636196136385700009510410452607787550747631201560743619098845397879802;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 7187825234779975349195938510966686423868944514844141584032091520617575821841;
    uint256 constant deltax2 = 15167963042598936201871911442372552125865590559139263583387664276363951575179;
    uint256 constant deltay1 = 3992969313533844667602556124657902836435467477463745801887651049519422523297;
    uint256 constant deltay2 = 4418481037195220326883310216950458228439821067777840620161157227529425796263;

    
    uint256 constant IC0x = 14037554855950702371500775098062591951299206266902716068909773367154606518737;
    uint256 constant IC0y = 8204798407741976053128371857995845621790312561493499344726304350121034545648;
    
    uint256 constant IC1x = 16662921520292743732338597574162611281472464073667325279354601580415093131056;
    uint256 constant IC1y = 17935002484083900753693692581966343385362764825519384067672451107336090493908;
    
    uint256 constant IC2x = 2982027756880684246651394302268809687339039076726249231294415159542835582422;
    uint256 constant IC2y = 5936288747776679021118374639562914030347731123789490953352337486408560280968;
    
    uint256 constant IC3x = 10842323014447666654572083366976139293480999855749884599265617286046002752162;
    uint256 constant IC3y = 2024494386806752653437858866341817989714205734308346173959791552062847792326;
    
    uint256 constant IC4x = 17375899938293976159010572612079951596742521383030232249261984586070569781594;
    uint256 constant IC4y = 15773939625996504630976125527586972899893686683264795227657323465928266915835;
    
    uint256 constant IC5x = 6267730586581247203448919295353599831728097982906840973423757718100200712722;
    uint256 constant IC5y = 20796964514427898161997698832825306115484562875935013976793400075759848627880;
    
    uint256 constant IC6x = 13297640909071511879943698707648682126028222003873047641441127728228771314567;
    uint256 constant IC6y = 19501242248510319063868867243252076163359879653445212555239161045035122433291;
    
    uint256 constant IC7x = 1431693383348174867671743982252948150363688112963447669315074441062402150628;
    uint256 constant IC7y = 20290036964128961742398746887730336484075890049776733124525430398387451848162;
    
    uint256 constant IC8x = 4143392219253911624781080755136823958746401915710863171088015770846273599463;
    uint256 constant IC8y = 20578384552810515320499366760409501102616971733566727886804323478447004530993;
    
    uint256 constant IC9x = 17415594792573319308257273616001986356594919233009079964904768960157746824470;
    uint256 constant IC9y = 11197693890194445957605975072962306015410194774816413634224206768025937853866;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[9] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
