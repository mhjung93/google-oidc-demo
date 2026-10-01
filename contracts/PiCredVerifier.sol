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
    uint256 constant deltax1 = 16344935270741978782881435939098307246834717924486101895600433837042487416836;
    uint256 constant deltax2 = 10032918232413898896349996931664746332349016697940054496694540486079083739426;
    uint256 constant deltay1 = 2730647606335062547690671336675506600466462417896230379487612948625253769484;
    uint256 constant deltay2 = 13697526031741227661233967604994413084196465159528767652487974309522734750853;

    
    uint256 constant IC0x = 8108450779454445717146781691653884785052829432437642205490059172179218037080;
    uint256 constant IC0y = 10313015882767983071655566667364199962336462947853645884806013009354736299197;
    
    uint256 constant IC1x = 14504631407450751889436382415138476015826361591323173388444449517120559189433;
    uint256 constant IC1y = 7101619127641352440786962308225338794749722614075518714944058904018469832508;
    
    uint256 constant IC2x = 14042042716789125889303290173877804150158911762338524906786501636021235849523;
    uint256 constant IC2y = 18557926127597351514466689469311766143642953123626991991250471026034811170905;
    
    uint256 constant IC3x = 6960743215057076984981089267517049922943993842366395059611516933151532720619;
    uint256 constant IC3y = 18072412179352515273769782672700210669195397204149144696116389064103579817400;
    
    uint256 constant IC4x = 901263358129359575280799143225644010637482103455014420617960665356644314738;
    uint256 constant IC4y = 8193259388443912724939502397981601871176003577417693812865736607104285728635;
    
    uint256 constant IC5x = 10212321643152610370715229060709235744132362144576704918517490806566779999122;
    uint256 constant IC5y = 17905393299186203185630081570682488917895411829607509858222110615438277464210;
    
    uint256 constant IC6x = 14591452889399533549107051765943448514195548107376722111742780706379869152895;
    uint256 constant IC6y = 15845867064383840178961067448130745355385657837077245672573053486105688316585;
    
    uint256 constant IC7x = 13744154208593626224505369292632376983034253862899756766474129690657851318127;
    uint256 constant IC7y = 21371935918370748814186196729565581845918141767169611702589061317833759295592;
    
    uint256 constant IC8x = 21148297880082275556079755859150541766438689099098509487000692391830976632132;
    uint256 constant IC8y = 4235159813271682269283271619323614572816739126434084168536872777290946834213;
    
    uint256 constant IC9x = 3454496654292002113734016304696255873246363280295376933560728290768076726123;
    uint256 constant IC9y = 21456792512432298439270948935310743946495192193040606515542441153787139267457;
    
    uint256 constant IC10x = 13590198761981504550532781485669744834658235746406373724240433978416015873773;
    uint256 constant IC10y = 12954567763219492345074210780053540780399483998980434220139367007345361468225;
    
    uint256 constant IC11x = 18251501846563025324395723509623331781112432194469273561238999516452095249450;
    uint256 constant IC11y = 19678512069954584056486474695321425620489534732088114650800494819574994828100;
    
    uint256 constant IC12x = 2127501239129905089873428149580718464715592805881214126234996074598282721048;
    uint256 constant IC12y = 16759041700067960914375380204452001882105150081845309249363299051617624980325;
    
    uint256 constant IC13x = 14764028831412099897693725407375280206919436489495161974688928582091904471815;
    uint256 constant IC13y = 6198973528671052994080062583007698911157710786297918838532603287065629483097;
    
    uint256 constant IC14x = 3007623596736814334533601100646730348214703481325233764972868086954669845080;
    uint256 constant IC14y = 12447360360213376746357634147316902737555004619397749830919110837547227149171;
    
    uint256 constant IC15x = 7762138022202643469525038495931868285895443223742077987826499762934801737722;
    uint256 constant IC15y = 15800811159890569503087817141543965195808772497975420044581127839515693583685;
    
    uint256 constant IC16x = 14196971638747682360457095920713072133561993553250847985780717529012954071085;
    uint256 constant IC16y = 19166538063355396618949718198377445181923998197717291271926727763326205562815;
    
    uint256 constant IC17x = 12459212777756678532413021704786897629617995412761084785677190323970488859621;
    uint256 constant IC17y = 204950978488613677358076390028583089567567584542376668604031351308394168993;
    
    uint256 constant IC18x = 4294393256438108152340175586198502327755940874189099119616870006052879987257;
    uint256 constant IC18y = 7509583363983697352725882210776854036444633903464969144159744876599499712655;
    
    uint256 constant IC19x = 7570438891016206618654289656451132064434656039951946801461334220020582558068;
    uint256 constant IC19y = 13205002696904881197140814805308089398552207297463975603800261193886596769476;
    
    uint256 constant IC20x = 21803101819686979618705352063343680974318702846863293490812543131655231282519;
    uint256 constant IC20y = 6277488776388215613773687568063683672579391617142664537920349292120749312266;
    
    uint256 constant IC21x = 4987973604103490790919853069905786808878324004388186524937573958905417575735;
    uint256 constant IC21y = 15106623334639187416033639908623000231250559984553177681039318562048569302348;
    
    uint256 constant IC22x = 14114543224837727260171976274700525436368503391386210017626888807026988368302;
    uint256 constant IC22y = 3202987805040561709779612700460662456031857244295621068987430851210367047234;
    
    uint256 constant IC23x = 14260924530377572992840586270926535087908765217033229779137440437775729758928;
    uint256 constant IC23y = 19506269092284126772044951791923386306378585638033037381943412891298068678919;
    
    uint256 constant IC24x = 1063939015226198138542016241072372080548116217804946980872730531337838103031;
    uint256 constant IC24y = 10845411916769835328858131399775689273966513243772743141650151344095176170737;
    
    uint256 constant IC25x = 15237819969406433482062516869614828492405290880036957885645719011305662862389;
    uint256 constant IC25y = 17703716532060996354481205901837720032087053155633651090165734380998141137171;
    
    uint256 constant IC26x = 8148442291371376092000659010871514455989008433363952548880255651225404021990;
    uint256 constant IC26y = 18324886842085928535518905169146505429360455862009922043938242603245483910467;
    
    uint256 constant IC27x = 19442502066792985700950150514031711296106004501412139637342313784623826669980;
    uint256 constant IC27y = 4594642647482216071538703028128991678697489432322070363898127420792731756830;
    
    uint256 constant IC28x = 7023267435624533244639358525923035792260656631448628453912026689107457839057;
    uint256 constant IC28y = 16553238272540229458898843147425604912811312373157433149198385821581583334085;
    
    uint256 constant IC29x = 6603587615082458929474667036258466909482836392066210773762795949939441997281;
    uint256 constant IC29y = 10153577323527958739990449111697774220404733546248299047696872242531166862731;
    
    uint256 constant IC30x = 8759181892364162548100544817701996742468001078537129099031849455881116420106;
    uint256 constant IC30y = 9847998298849584328880104990727136468611865299376447051166222944960413824520;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[30] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                

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
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
