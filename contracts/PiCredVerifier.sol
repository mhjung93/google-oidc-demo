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

contract PiCredVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 17274321419396066921132561134048296040456946886140808124305891964931559917907;
    uint256 constant deltax2 = 19515740795961043031593059206610026301734397078336412277133375594817209607112;
    uint256 constant deltay1 = 17581569647181620708481264735165648744505866394833971055957709049916928998476;
    uint256 constant deltay2 = 90011914541164790048444163209607937462238551346396896116067072819319366545;

    
    uint256 constant IC0x = 15583229571941955039048204856952097502187799648132471913912819687478109455801;
    uint256 constant IC0y = 9182892805764963027919658051461545781581038056327083181519454306151426545797;
    
    uint256 constant IC1x = 12439912431782516492419278272317141718546550265991417820151194859530236232361;
    uint256 constant IC1y = 1343756382838404446906799717404091012284954366271949558273233058162985411304;
    
    uint256 constant IC2x = 1014603423743841965847762780586728058991122646007818492202537367971784128547;
    uint256 constant IC2y = 19910744730796552749356979082842899441221461507208569775946291611389186668559;
    
    uint256 constant IC3x = 11352746657044733384181390814733707121906065738124285943669561540897591489552;
    uint256 constant IC3y = 19505153552825363418887566035661505686121772577622127291254477741915318805856;
    
    uint256 constant IC4x = 20479456740813426901289750665780595258174879975098967242415177872275034402667;
    uint256 constant IC4y = 7433747179691109160118733955812495860932858616489617281887795963618577573888;
    
    uint256 constant IC5x = 811453806974390332471107690212063903339159306205593721541284849243169788597;
    uint256 constant IC5y = 11130406809538436482846923808918462859940309843545902995314371958325754676448;
    
    uint256 constant IC6x = 10455611587359852362545161234106818399489758085061094645238772957046013257324;
    uint256 constant IC6y = 15562716429741669151729232044199765732621786608586236024166848618170899774028;
    
    uint256 constant IC7x = 12115831681053597089746201925820582042349775132542456841449771630038941467966;
    uint256 constant IC7y = 8577343471997674603348382619095125475942490613853811626313578455251462138960;
    
    uint256 constant IC8x = 18775638996606049655983953042733051962319585153470070109592823901769092432615;
    uint256 constant IC8y = 21738218222780734936408372943315439062932880225337104233936701649848930818946;
    
    uint256 constant IC9x = 1151860016634556598667091446341935719830139996426252070189694576852954696593;
    uint256 constant IC9y = 21523640890193486712133377829353904832648764332938385383462234247693754415111;
    
    uint256 constant IC10x = 12434562558371045793912254990282904477478869914822446850746767509850714298105;
    uint256 constant IC10y = 12258140294339917623900320888266040927424484666970143687429274682682753441765;
    
    uint256 constant IC11x = 20884141426482426243537519456457880668480119024162900653273201924205133618870;
    uint256 constant IC11y = 8425123438173668378269998006927362903941172269055370341527477464205374133108;
    
    uint256 constant IC12x = 89291439060884632072472529033883353078402772089702019620788150184045396851;
    uint256 constant IC12y = 10135699970296105736196241877163174020686753071127151612002662126741058320588;
    
    uint256 constant IC13x = 21686973435021496882906108008800041969074315408467465328769054212575974646558;
    uint256 constant IC13y = 4146432701380531754625111473181936768288998666651745421489208833164668124081;
    
    uint256 constant IC14x = 9184614330095249818217577338525234642314071861025795270087393322096337026144;
    uint256 constant IC14y = 2889872143802241236814492356668551085700574692674999496324984492460790165077;
    
    uint256 constant IC15x = 20109182015270907269305928610052078009603666810189862312781628355852906370544;
    uint256 constant IC15y = 6664317744915022449145318499424645974057741359412594554107340966221893453225;
    
    uint256 constant IC16x = 2328633588919796615090928042861502667803768308985969505708850762509794115175;
    uint256 constant IC16y = 12698673826155589909421448409787689643245830047674805429009971948384487481203;
    
    uint256 constant IC17x = 9386540027363808486551114235861144898035352247158334199108857513867317287624;
    uint256 constant IC17y = 16897874064107318096075328267227528183771885854669343189106074793148086970429;
    
    uint256 constant IC18x = 8941379209961201338741984516736431677410419824171839524800606486654594129835;
    uint256 constant IC18y = 8097703806133004380258850418990628336490679256842504298247564772232475182267;
    
    uint256 constant IC19x = 2486763698125284624567674302100517026560691237937592712830113801014159918976;
    uint256 constant IC19y = 13658661079139152195738354079810764051290900574455887343692351140516442894903;
    
    uint256 constant IC20x = 7441976535196782884237305810996916568747633047785930138494715735687862254087;
    uint256 constant IC20y = 17999858657967623236649464754426157287710197791553616737252826023223056768888;
    
    uint256 constant IC21x = 8539133220477972230172676279557325116851559179861056043226582903745590243934;
    uint256 constant IC21y = 6224234237573638886523426109765123044596516292662483812686404309987994210808;
    
    uint256 constant IC22x = 14567692174965161878506794578902764208317381571376260093344445706047349215708;
    uint256 constant IC22y = 2123433108345779495078840396030769216451484315471205587728829685905668646336;
    
    uint256 constant IC23x = 9673985919020788828798670455966907274129845840864161106930922770672698277715;
    uint256 constant IC23y = 9053280572171193019128338006028902593446092828084780825013821030281308791529;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[23] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                

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
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
