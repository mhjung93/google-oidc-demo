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
    uint256 constant deltax1 = 2689774426978607678028500417163684340732227011666239004912592445938804092015;
    uint256 constant deltax2 = 9353916645603356458487660471199764735260489404420291312947669863251840572980;
    uint256 constant deltay1 = 4995624610402755474527919471533823768949857401237282991485871712146327949466;
    uint256 constant deltay2 = 7115577038585587160266594906139537923973803844117372417621328030620196051986;

    
    uint256 constant IC0x = 19971517996416748685810612442778416388573371053585797073371274709042513192061;
    uint256 constant IC0y = 3196234538141231076215420463404663987786460469691376576833770698936678116706;
    
    uint256 constant IC1x = 18639142752763814098527512561519591825513767025825869407746094346759324227175;
    uint256 constant IC1y = 18267430085444551049959896004220741043590584276319265748366690049517241471475;
    
    uint256 constant IC2x = 19179022220676390155221770665824707385301990482804413243613730688718497448046;
    uint256 constant IC2y = 11571546920219149677936582706021010028808508585518041310883884097950629221267;
    
    uint256 constant IC3x = 14945595005585288814701461997043796267988481148579093461806240946222375447703;
    uint256 constant IC3y = 10416741032369066840124135866454368394954000122846195076092205531824266600616;
    
    uint256 constant IC4x = 11099038507979441950268147309149273566394058606779960502135476243972274655784;
    uint256 constant IC4y = 2660750251516221189972149993690687467694044560552847915906917934954480354360;
    
    uint256 constant IC5x = 3050610310018322056529578117154105524172586432736846493368955189499255970228;
    uint256 constant IC5y = 8201115164611571756970742715812866580512248519069243126941439252979408731763;
    
    uint256 constant IC6x = 20867292969712349757003206026578740912518683903889776494134431550085245809138;
    uint256 constant IC6y = 13584026566792320102586697051612871579791022224370038608014684633847721796942;
    
    uint256 constant IC7x = 5577046791505458814145257277219995877051587716427604390267371619503660197343;
    uint256 constant IC7y = 19191170375168744584752219060337109438194019199137404348267120071391234029568;
    
    uint256 constant IC8x = 9690638486383051692534903641753884142097687314927387158000289405939070724919;
    uint256 constant IC8y = 19932356701221195814139345214285182741583604766138679980038107004948547096785;
    
    uint256 constant IC9x = 14848840940104640476170149378955871984659422225304714479172983724161786453863;
    uint256 constant IC9y = 9886559140803078858159104206574230162388923620743589389225101874843533347562;
    
    uint256 constant IC10x = 7213096614320982263827029322251342220649241339411129311285861849639137064675;
    uint256 constant IC10y = 6101696984162353551150730872099883693372661845318644957159572494697897763907;
    
    uint256 constant IC11x = 10380650246865505741253070676413727722682692597701942411843820049016962610486;
    uint256 constant IC11y = 329851895327812589901309491126545375930681121756232805202194723096228788380;
    
    uint256 constant IC12x = 13022581504064455359465896549013915790616279492163869838817950160089198642490;
    uint256 constant IC12y = 4843749216735590264639417147169604614008255624942271986486885773964899525449;
    
    uint256 constant IC13x = 15271115696449686280547157331280466522818045954028872981052617066160876194946;
    uint256 constant IC13y = 12743915301500088019564247274756612721000139275512461689795968770103795417884;
    
    uint256 constant IC14x = 3261392679773162794177473244456768686394206862685232596592620127740111370742;
    uint256 constant IC14y = 10723420335257300554428205947394056387693840360484511874843008978230356027983;
    
    uint256 constant IC15x = 5291442876076928660628607518488210017835083202403767827313502152091313290990;
    uint256 constant IC15y = 4349661108164792686749414829361192761423542784617898153936528603016139272912;
    
    uint256 constant IC16x = 6561669537468171671074378557519093372855323937344412151438770518765955073332;
    uint256 constant IC16y = 217524787711578045865012710578548454646544814214303889371406409207577897479;
    
    uint256 constant IC17x = 3222322935103033727129064796842281226242549924987071053786419562851628220018;
    uint256 constant IC17y = 17330235222385899560189254870423351973920245609778116917094680619053949699975;
    
    uint256 constant IC18x = 15309927429358219435700388556585853842704810149329852563444361624519323901202;
    uint256 constant IC18y = 19392702880424629137398183649319783309749604149160473820599136027918033429753;
    
    uint256 constant IC19x = 15134531806916055389021510468527592685331050626330012519849797522744551020340;
    uint256 constant IC19y = 1820129970904499062793681690096679726976729863726346682147330357837686279653;
    
    uint256 constant IC20x = 6776833731304160965780250020689144428954393229713503629967742079836251759761;
    uint256 constant IC20y = 9441880954727689332156140019222147316779589177001700716076608241982489240735;
    
    uint256 constant IC21x = 3757816608615256283352538982764909649807229140420761363378548103145697316277;
    uint256 constant IC21y = 6135975650185859544327133458262459359545470629381682931088494252460780026150;
    
    uint256 constant IC22x = 1709830585363370739439322581468979256429879614136450983006446299263918798475;
    uint256 constant IC22y = 336582289421486868020443799625123096875361180805972717658127340055567789761;
    
    uint256 constant IC23x = 10278220546010288654240084990510136489168057224436661713832121154834140832544;
    uint256 constant IC23y = 395224224361634273592716275898199280179372971427222423580495771346907323181;
    
    uint256 constant IC24x = 20543197718039474661863821504147152718130564943764152588446751166640074108174;
    uint256 constant IC24y = 12948514714983861391423059773207079745706476800431865575964270075064001028733;
    
    uint256 constant IC25x = 2118519784933612792674598838781403865917205357725183866406873109859701003055;
    uint256 constant IC25y = 4790517904216123371604801544690163864352520551433776294647310918361588604029;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[25] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                

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
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
